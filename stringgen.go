package main

import "math"

type StringGen struct {
	charset    string // The set of characters to choose from
	charsetlen int    // Length of charset

	length int // lenght of the generated string

	indexdata []int  // Index data for where we are in each byte
	data      []byte // The actual bytes that make up the string
	done      int    // If a leading position is done, we increment this
	first     bool
}

func NewStringGen(charset string, length int) *StringGen {
	sg := StringGen{
		charset:    charset,
		charsetlen: len(charset),

		length: length,

		indexdata: make([]int, length),
		data:      make([]byte, length),

		done:  0,
		first: true,
	}
	return &sg
}

func (sg *StringGen) Complexity() int64 {
	return int64(float32(math.Pow(float64(sg.charsetlen), float64(sg.length))))
}

func (sg *StringGen) Next() bool {
	if sg.first {
		for i := 0; i < sg.length; i++ {
			sg.data[i] = sg.charset[0]
		}
		sg.first = false
		return true
	}

	if sg.done == sg.charsetlen {
		return false
	}

	for i := sg.length - 1; i >= 0; i-- {
		if sg.indexdata[i] == sg.charsetlen-1 {
			sg.indexdata[i] = 0
			sg.data[i] = sg.charset[0]
		} else {
			sg.indexdata[i]++
			sg.data[i] = sg.charset[sg.indexdata[i]]

			if sg.done == i && sg.indexdata[i] == sg.charsetlen-1 {
				sg.done++
			}

			break
		}
	}
	return true
}

func (sg *StringGen) String() string {
	return string(sg.data)
}
