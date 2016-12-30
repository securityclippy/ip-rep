package filehelper

import (
	"os"
	"bufio"
	"net"
	"fmt"
	"strings"
	"io/ioutil"
	"log"
	"net/http"
)

type IPReport struct {
	Address string
	Bad int
	Good int
}

func CheckDNSBlacklist(dns_bl string, ans_channel chan string){
	a, _ := net.LookupHost(dns_bl)
	if a != nil {
		ans_channel <- dns_bl
	} else{
		ans_channel <- ""
	}
}

func GetActiveBlacklists()([]string){
	//verify that all our dns blacklists are actually responding before we query them a bajillion times
	//returns a string slice of valid dns_blacklists which have responded
	dns_bl_path := "dns_bls.txt"
	dns_inFile, _ := os.Open(dns_bl_path)
  	defer dns_inFile.Close()
	ans_channel := make(chan string)
	dns_scanner := bufio.NewScanner(dns_inFile)
	dns_scanner.Split(bufio.ScanLines)
	valid_dns_list := make([]string, 0)
	c := 0
	for dns_scanner.Scan() {
		c++
		dns_scanner.Text()
		go CheckDNSBlacklist(dns_scanner.Text(), ans_channel)
	}
	for i := 0; i < c; i++{
		j := <-ans_channel
		if j != "" {
			valid_dns_list = append(valid_dns_list, j)
		}
	}
	return valid_dns_list
}

func GetTextBlacklists() {
	fmt.Println("Updating text blacklists...")
	blacklist_uris := []string{"torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv",
		"rules.emergingthreats.net/blockrules/compromised-ips.txt",
		"reputation.alienvault.com/reputation.data",
		"www.blocklist.de/lists/bruteforcelogin.txt",
		"dragonresearchgroup.org/insight/sshpwauth.txt",
		"dragonresearchgroup.org/insight/vncprobe.txt",
		"www.openbl.org/lists/date_all.txt",
		"www.nothink.org/blacklist/blacklist_malware_http.txt",
		"www.nothink.org/blacklist/blacklist_ssh_all.txt",
		"rules.emergingthreats.net/blockrules/compromised-ips.txt",
		"antispam.imp.ch/spamlist",
		"www.dshield.org/ipsascii.html?limit=10000",
		"malc0de.com/bl/ip_blacklist.txt",
		"hosts-file.net/rss.asp"}
	c := make(chan struct{})
	num_threads := 0
	for _, blacklist_uri := range blacklist_uris {
		num_threads ++
		go CreateBlacklist(blacklist_uri, c)
	}
	for i := 0; i < num_threads; i++ {
		<-c
	}
	fmt.Print("done\n")
}

func CreateBlacklist(blacklist_uri string, c chan struct{}) {
	blacklist_uri = "http://" + blacklist_uri
	content := GetTextBlacklistContent(blacklist_uri)
	WriteBlacklist(blacklist_uri, content)
	c <- struct{}{}
	return
}

func WriteBlacklist(blacklist_uri, blacklist_content string){
	bl_name := strings.Split(blacklist_uri, "/")[2]
	f, _ := ioutil.ReadDir(".blacklists")
	for _, file := range f {
		os.Remove(file.Name())
	}
	if _, err := os.Stat(".blacklists"); os.IsNotExist(err) {
		os.Mkdir(".blacklists", 0755)
	}
	err := ioutil.WriteFile(".blacklists/"+bl_name+".list", []byte(blacklist_content), 0644)
	check_err(err)
	return
}

func check_err(e error) {
    if e != nil {
        log.Panic(e)
    }
}

func GetTextBlacklistContent(list_url string) (body string) {
	resp, err := http.Get(list_url)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: Failed to retrieve \"" + list_url + "\"")
		return
	}
	b, _ := ioutil.ReadAll(resp.Body)
	body = string(b)
	return body
	}

func CheckAgainstTextLists(ipaddress string) (IPReport) {
	var report IPReport
	report.Address = ipaddress
	f, _ := ioutil.ReadDir(".blacklists")
	for _, file := range f {
		text, err := ioutil.ReadFile(".blacklists/"+file.Name())
		if err != nil{
			print(err)
		}
		s := string(text)
		if strings.Contains(s, ipaddress) {
			report.Bad ++
		} else {
			report.Good ++
		}
	}
	return report
}

func ReadAddressFile(fn string) ([]string){
	var iplist []string
	fmt.Println(fn)
	inFile, err:= os.Open(fn)
	fmt.Println(inFile)
	check_err(err)
  	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		iplist = append(iplist, scanner.Text())
	}
	return iplist
}
