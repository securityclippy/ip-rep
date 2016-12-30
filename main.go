package main

import (
	"fmt"
	"github.com/securityclippy/ip-rep/helpers/dnshelper"
	"github.com/docopt/docopt-go"
	"strconv"
	"github.com/securityclippy/ip-rep/helpers/filehelper"
)

type IPReport struct {
	address string
	bad int
	good int
}


func CheckIPAddress(ipaddress string, ratelimit int, blacklists []string) (IPReport){
	var results IPReport
	ch := make(chan string)
	rl_chan := make(chan string, ratelimit)
	ipaddr := ipaddress
	results.address = ipaddr
	//note that this particular goroutine is limited by the number of lists in the blacklists variable
	//while the ratelimit may be set higher, the ACTUAL ratelimit cannot increase beyond the size of the
	//blacklists slice
	for i := range blacklists {
		bl := blacklists[i]
		qr := dnshelper.CreateReverseQuery(ipaddr, bl)
		go dnshelper.Txtlookup(qr, ch, rl_chan)
	}
	for i := 0; i < len(blacklists); i++ {
		rep := <- ch
		if rep == "true" {
			results.bad ++
		} else {
			results.good ++
		}
	}
	//now check our text based lists that we downloaded...
	text_results := filehelper.CheckAgainstTextLists(ipaddress)
	results.good += text_results.Good
	results.bad += text_results.Bad
	return results
}


func main() {
	usage := `ip-rep
Usage:
  ip-rep -r <file>
  --ratelimit <ratelimit>`

	args, _ := docopt.Parse(usage, nil, true, "0.1", false)
	fn := args["<file>"]
	file := fn.(string)
	ratelimit := args["<ratelimit>"]
	rl := ratelimit.(string)
	r, _ := strconv.Atoi(rl)
	blacklists := filehelper.GetActiveBlacklists()
	//update our text-based blacklists
	//filehelper.GetTextBlacklists()
	var ipaddresses []string
	ipaddresses = filehelper.ReadAddressFile(file)
	fmt.Println("Adding "+strconv.Itoa(r/len(blacklists))+" go routines to meet ratelimit")
	fmt.Println("scanning "+strconv.Itoa(len(ipaddresses)))
	for ip := range ipaddresses {
		results := CheckIPAddress(ipaddresses[ip], r, blacklists)
		fmt.Println(results)
	}
}
