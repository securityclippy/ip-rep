package dnshelper

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"strings"
	"time"
)

func Txtlookup(qr string, answer_chan chan string, rl_chan chan string){
	rl_chan <- "holding"
	// this is here to give us a consistent rate limit.  this effectively means that a given goroutine
	// cannot take LESS than 1 second, thus scaling our concurrent lookups to $ratelimit/per second
	// ie ratelimit = 10, we can max (at most) 10 lookups a second
	time.Sleep(100 * time.Millisecond)
	//give 3x priority to google dns as the ratelimit is much better
	dns_servers := []string{"8.8.8.8:53",
		"8.8.4.4:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
		"208.67.222.222:53",
		"208.67.220.220:53",
		//"4.2.2.1:53",
		//"4.2.2.2:53",
		//"4.2.2.3:53",
		//"4.2.2.4:53",
		//"4.2.2.5:53",
		//"4.2.2.6:53",
		}
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{qr, dns.TypeTXT, dns.ClassINET}
	dns_srv :=  dns_servers[rand.Intn(len(dns_servers))]
	in, err := dns.Exchange(m1, dns_srv)
	var ans string
	if in != nil{
		//fmt.Println(in)
		if len(in.Answer) > 0 {
			//fmt.Println(in.Answer)
			ans = "true"
		} else{
			ans = "false"
		}
	} else {
		ans = "false"
	}
	if err != nil {
		ans = "false"
		fmt.Println("Error in DNS lookup.  If these continue, please consider reducing your query rate \n" +
			"or taking this server out of rotation")
		fmt.Println("Responsible DNS server: "+dns_srv)
	}
	answer_chan<- ans
	<- rl_chan
}

func Reverseip(ipaddr string) (string){
	var addr_slice [4]string
	a := 3
	for _, i := range strings.Split(ipaddr, "."){
		addr_slice[a] = i
		a--
	}
	rev := strings.Join(addr_slice[:], ".")
	return rev
}

func CreateReverseQuery(ipaddr, dns_blacklist string) (string){
	query := Reverseip(ipaddr) + "." + dns_blacklist + "."
	return query
}

