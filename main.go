package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

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
	server := flag.String("server", "", "DC to connect to, use IP or full hostname - will try autodection if not supplied")
	port := flag.Int("port", 389, "LDAP port to connect to (389 or 636 typical)")
	tlsmodeString := flag.String("tlsmode", "NoTLS", "Transport mode (TLS, StartTLS, NoTLS)")
	ignoreCert := flag.Bool("ignorecert", true, "Disable certificate checks")

	inputname := flag.String("input", "", "file to read usernames from, uses stdin if not supplied")
	outputname := flag.String("output", "", "file to write detected usernames to, uses stdout if not supplied")

	parallel := flag.Int("parallel", 8, "how many connections to run in parallel")

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

	var pb *progressbar.ProgressBar
	input := os.Stdin
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

			pb = progressbar.NewOptions(
				lines,
				progressbar.OptionSetDescription("Progress"),
				progressbar.OptionShowIts(),
			)
		}
	}

	names := bufio.NewScanner(input)
	names.Split(bufio.ScanLines)

	// AUTODETECTION
	var domain string
	if *server == "" {
		// We only need to auto-detect the domain if the server is not supplied
		log.Println("No server supplied, auto-detecting")
		domain = strings.ToLower(os.Getenv("USERDNSDOMAIN"))
		if domain == "" {
			// That didn't work, lets try something else
			f, err := fqdn.FqdnHostname()
			if err == nil && strings.Contains(f, ".") {
				log.Print("No USERDNSDOMAIN set - using machines FQDN as basis")
				domain = strings.ToLower(f[strings.Index(f, ".")+1:])
			}
		}
		if domain == "" {
			log.Fatal("Domain auto-detection failed")
		} else {
			log.Printf("Auto-detected domain as %v", domain)
		}
	}

	if *server == "" {
		// Auto-detect server
		cname, servers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+domain)
		if err == nil && cname != "" && len(servers) != 0 {
			*server = strings.TrimRight(servers[0].Target, ".")
			log.Printf("AD controller detected as: %v", *server)
		} else {
			log.Fatal("AD controller auto-detection failed, use '--server' parameter")
		}
	}

	// END OF AUTODETECTION

	if len(*server) == 0 {
		log.Fatal("missing AD controller server name - please provide this on commandline")
	}

	inputqueue := make(chan string, 128)
	outputqueue := make(chan string, 128)

	var jobs sync.WaitGroup

	jobs.Add(*parallel)
	for i := 0; i < *parallel; i++ {
		go func() {
			var conn *ldap.Conn
			switch tlsmode {
			case NoTLS:
				conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", *server, *port))
			case StartTLS:
				conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", *server, *port))
				if err == nil {
					err = conn.StartTLS(&tls.Config{ServerName: *server})
				}
			case TLS:
				config := &tls.Config{
					ServerName:         *server,
					InsecureSkipVerify: *ignoreCert,
				}
				conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", *server, *port), config)
			}

			if err != nil {
				log.Printf("Problem connecting to LDAP server: %v", err)
				jobs.Done()
				return
			}

			for username := range inputqueue {
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
			}
			jobs.Done()
		}()
	}

	go func() {
		for username := range outputqueue {
			fmt.Fprintln(output, username)
		}
	}()

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
	jobs.Wait()
	close(outputqueue)
}
