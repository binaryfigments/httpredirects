package httpredirects

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/idna"

	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	URL          string       `json:"url,omitempty"`
	Redirects    []*Redirects `json:"redirects,omitempty"`
	Hosts        []*Hosts     `json:"hosts,omitempty"`
	Error        bool         `json:"error,omitempty"`
	ErrorMessage string       `json:"errormessage,omitempty"`
}

// Redirects struct
type Redirects struct {
	Number     int    `json:"number"`
	StatusCode int    `json:"statuscode,omitempty"`
	URL        string `json:"url,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// Hosts struct
type Hosts struct {
	Hostname     string   `json:"hostname,omitempty"`
	IPv4         []string `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	Error        bool     `json:"error,omitempty"`
	ErrorMessage string   `json:"errormessage,omitempty"`
}

// Get function
func Get(redirecturl string, nameserver string) *Data {
	r := new(Data)

	r.URL = redirecturl

	u, err := url.Parse(redirecturl)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}

	var fqdn string

	fqdn, _, err = net.SplitHostPort(u.Host)
	if err != nil {
		fqdn = u.Host
	}

	// Valid server name (ASCII or IDN)
	fqdn, err = idna.ToASCII(fqdn)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}

	// Resolve IP address
	_, err = net.ResolveIPAddr("ip", fqdn)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}

	// Create urllist map
	var urllist map[string]bool
	urllist = make(map[string]bool)

	// Start URL to urllist
	addurl, _ := hostFromURL(redirecturl)
	urllist[addurl] = true

	// set nextURL for routine
	nextURL := redirecturl

	var i int

	// max 20 times
	for i < 20 {
		// set client to CheckRedirect, not following the redirect
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}

		// nextURL prefix check for incomplete
		if caseInsenstiveContains(nextURL, "http://") == false && caseInsenstiveContains(nextURL, "https://") == false {
			// TODO: Set warning
			nextURL = redirecturl + nextURL
		}

		// Repair the request
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			r.Error = true
			r.ErrorMessage = err.Error()
			return r
		}

		// Set User-Agent
		req.Header.Set("User-Agent", "Golang_Research_Bot/3.0")

		// Do the request.
		resp, err := client.Do(req)
		if err != nil {
			r.Error = true
			r.ErrorMessage = err.Error()
			return r
		}
		defer resp.Body.Close()

		// Set soms vars.
		redirect := new(Redirects)
		redirect.Number = i
		redirect.StatusCode = resp.StatusCode
		redirect.URL = resp.Request.URL.String()
		redirect.Protocol = resp.Proto

		// Only unique hosts in hostlist
		addurl, _ := hostFromURL(resp.Request.URL.String())
		if urllist[addurl] == false {
			urllist[addurl] = true
		}

		r.Redirects = append(r.Redirects, redirect)

		if resp.StatusCode == 200 || resp.StatusCode > 303 {
			break
		} else {
			nextURL = resp.Header.Get("Location")
			i++
		}
	}

	for key := range urllist {
		host := getHosts(key, nameserver)
		r.Hosts = append(r.Hosts, host)
	}

	return r
}

func hostFromURL(geturl string) (string, error) {
	u, err := url.Parse(geturl)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// getHosts function
func getHosts(geturl string, nameserver string) *Hosts {
	r := new(Hosts)

	r.Hostname = geturl

	cname, err := GetCNAME(r.Hostname, nameserver)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}

	if len(cname) > 0 {
		r.CNAME = cname
		return r
	}

	ar, err := GetA(r.Hostname, nameserver)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}
	r.IPv4 = ar

	aaaar, err := GetAAAA(r.Hostname, nameserver)
	if err != nil {
		r.Error = true
		r.ErrorMessage = err.Error()
		return r
	}
	r.IPv6 = aaaar

	return r

}

// GetCNAME function
func GetCNAME(hostname string, nameserver string) (string, error) {
	var cname string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return "none", err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.CNAME); ok {
			cname = r.Target
		}
	}
	return cname, nil
}

// GetA function
func GetA(hostname string, nameserver string) ([]string, error) {
	var record []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.A); ok {
			record = append(record, r.A.String())
		}
	}

	return record, nil
}

// GetAAAA function
func GetAAAA(hostname string, nameserver string) ([]string, error) {
	var record []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.AAAA); ok {
			record = append(record, r.AAAA.String())
		}
	}

	return record, nil
}

func caseInsenstiveContains(a, b string) bool {
	return strings.Contains(strings.ToUpper(a), strings.ToUpper(b))
}
