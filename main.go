
import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/jamesbcook/print"
	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nessus"
	"github.com/lair-framework/go-nmap"
	"gitlab.ap.optivlabs.com/attack-pen-all/drone-asm/imports"
)

var (
	debug       bool
	debugWriter func(format string, v ...interface{})
	binVersion  string
	gitCommit   string
)

const (
	tool     = "drone-asm"
	toolInfo = `
Takes an old lair project and compares it to a Nessus scan. If an old vulnerability
is in the new scan turn that finding grey. Once the old project is updated it
is uploaded to a new project in lair.`
	usage = `
Usage:
  drone-asm [options]
Options:
  -blacksheepwall     blackssheepwall output        (required)
  -nessus             nessus scan output            (required)
  -nmap               nmap scan output xml format   (required)
  -oldLair            lair id for old project       (required)
  -newLair            lair id for new project       (required)
  -d                  print debug information
  -k                  allow insecure SSL connections
  -v                  show version and exit
  -h                  show usage and exit
`
)

func debugSetup(debugging bool, writer *io.Writer) {
	debugWriter = print.Debugf(debugging, writer)
}

type flags struct {
	nessus   string
	nmap     string
	newLair  string
	tempLair string
	oldLair  string
	version  bool
	insecure bool
	debug    bool
}

type recolor struct {
	hosts   []string
	service map[string][]int
}

func flagSetup() *flags {
	nessus := flag.String("nessus", "", "nessus file to import")
	nmap := flag.String("nmap", "", "nmap file to import")
	oldLair := flag.String("oldLair", "", "Old lair project id")
	tmpLair := flag.String("tmpLair", "", "Temp lair project id")
	newLair := flag.String("newLair", "", "New lair project id")
	debug := flag.Bool("d", false, "print debug output")
	showVersion := flag.Bool("v", false, "print tool version")
	insecureSSL := flag.Bool("k", false, "don't validate ssl cert")
	flag.Usage = func() {
		fmt.Println(toolInfo)
		fmt.Println(usage)
	}
	flag.Parse()
	var out io.Writer
	out = os.Stdout
	debugSetup(*debug, &out)
	return &flags{nessus: *nessus, nmap: *nmap, debug: *debug,
		insecure: *insecureSSL, version: *showVersion, newLair: *newLair,
		oldLair: *oldLair, tempLair: *tmpLair,
	}
}

func main() {
	flags := flagSetup()
	if flags.version {
		fmt.Printf("./%s v%s %s\n", tool, binVersion, gitCommit)
		os.Exit(0)
	}
	if flags.nessus == "" || flags.nmap == "" ||
		flags.oldLair == "" || flags.newLair == "" {
		print.Badln("Missing a required flag")
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		print.Badln("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		print.Badf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		print.Badln("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		print.Badln("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: flags.insecure,
	})
	if err != nil {
		print.Badf("Fatal: Error setting up client: Error %s\n", err.Error())
	}
	projectExport, err := c.ExportProject(flags.oldLair)
	if err != nil {
		print.Badf("Fatal: Unable to import project. Error %s\n", err.Error())
	}
	print.Statusln("Exported Lair project")
	buf, err := ioutil.ReadFile(flags.nessus)
	if err != nil {
		print.Badf("Fatal: Could not open file. Error %s\n", err.Error())
	}
	nessusData, err := nessus.Parse(buf)
	if err != nil {
		print.Badf("Fatal: Error parsing nessus data. Error %s\n", err.Error())
	}
	print.Statusln("Parsed Nessus xml file")

	nmapData, err := nmap.Parse(buf)
	if err != nil {
		print.Badf("Could not parse nmap file. Error %s\n", err.Error())
	}
	print.Statusln("Parsed Nmap file")

	print.Statusln("Working on making new json file")

	makeJSONFile(c, flags.oldLair, *nessusData, *nmapData)

	buf, err = ioutil.ReadFile(flags.nessus)
	if err != nil {
		print.Badf("Fatal: Could not open file. Error %s\n", err.Error())
	}
	nessusData, err = nessus.Parse(buf)
	if err != nil {
		print.Badf("Fatal: Error parsing nessus data. Error %s\n", err.Error())
	}

	print.Statusln("Checking for old vulns with new hosts")
	sameVulnNewHostCheck(projectExport, nessusData)
	nessusProject, err := imports.Nessus(nessusData, flags.newLair, nil, false)
	if err != nil {
		print.Badln(err)
	}

	print.Statusln("Checking for old hosts for new ports")
	recol := portCheck(&projectExport, nmapData)
	nmapProject, err := imports.Nmap(nmapData, flags.newLair, nil)
	if err != nil {
		print.Badln(err)
	}

	debugWriter("recolor data %v\n", recol)
	for x, nmapHost := range nmapProject.Hosts {
		debugWriter("Looking at %s\n", nmapHost.IPv4)
		for _, recolHost := range recol.hosts {
			if nmapHost.IPv4 == recolHost {
				print.Goodf("Setting host %s blue\n", nmapHost.IPv4)
				nmapProject.Hosts[x].Status = lair.StatusBlue
			}
		}
		for recolHost, recolServices := range recol.service {
			debugWriter("Looking at services %v\n", recolServices)
			if nmapHost.IPv4 == recolHost {
				for _, recolService := range recolServices {
					for i, nmapService := range nmapHost.Services {
						if recolService == nmapService.Port {
							print.Goodf("Setting %s service %d blue\n", nmapHost.IPv4, recolService)
							nmapProject.Hosts[x].Services[i].Status = lair.StatusBlue
						}
					}
				}
			}
		}
	}

	proj := &lair.Project{}
	proj.Tool = tool
	proj.ID = flags.newLair
	proj.Commands = append(proj.Commands, lair.Command{Command: "ASM Upload", Tool: "Drone ASM"})

	proj.Hosts = append(proj.Hosts, nessusProject.Hosts...)
	proj.Issues = append(proj.Issues, nessusProject.Issues...)
	proj.Hosts = append(proj.Hosts, nmapProject.Hosts...)

	uploadProject(c, proj)
	print.Goodln("Success: project uploaded")
}

func makeJSONFile(c *client.C, oldLairID string, nessusData nessus.NessusData, nmapData nmap.NmapRun) {
	projectExport, err := c.ExportProject(oldLairID)
	if err != nil {
		print.Badf("Fatal: Unable to import project. Error %s\n", err.Error())
	}

	projectExport.Tool = tool
	projectExport.ID = oldLairID

	/*
		We have to look at current and previous issues. If there are matching vulns,
		we'll add the hosts to the old project and remove the finding from the nessus
		scan. If we don't do this duplicate vuln names are added to the project.
	*/
	for i, host := range nessusData.Report.ReportHosts {
		for j, item := range host.ReportItems {
			for k, issue := range projectExport.Issues {
				if item.PluginName == issue.Title {
					notFound := true
					for _, previousHost := range issue.Hosts {
						if host.Name == previousHost.IPv4 {
							notFound = false
						}
					}
					if notFound {
						projectExport.Issues[k].Hosts = append(projectExport.Issues[k].Hosts,
							lair.IssueHost{IPv4: host.Name, Port: item.Port, Protocol: item.Protocol},
						)
					}
					nessusData.Report.ReportHosts[i].ReportItems[j] = nessus.ReportItem{}
				}
			}
		}
	}

	print.Statusln("Uploading Nessus data to old project")
	nessusProject, err := imports.Nessus(&nessusData, oldLairID, nil, false)
	if err != nil {
		print.Badln(err)
	}
	projectExport.Hosts = append(projectExport.Hosts, nessusProject.Hosts...)
	projectExport.Issues = append(projectExport.Issues, nessusProject.Issues...)

	print.Statusln("Uploading Nmap data to old project")
	nmapProject, err := imports.Nmap(&nmapData, oldLairID, nil)
	if err != nil {
		print.Badln(err)
	}
	projectExport.Hosts = append(projectExport.Hosts, nmapProject.Hosts...)

	print.Statusln("Making everything that's grey blue")
	makeProjectBlue(&projectExport)
	projectExport.Tool = tool
	projectExport.Commands = append(projectExport.Commands, lair.Command{Command: "Everything Blue", Tool: tool})

	print.Statusln("Writing new json file")
	data, err := json.Marshal(projectExport)
	if err != nil {
		print.Badln(err)
	}
	fileName := fmt.Sprintf("new-scan-%s.json", time.Now().Format("Jan-2-15:04:05"))
	if err := ioutil.WriteFile(fileName, data, 0644); err != nil {
		print.Badln(err)
	}

	print.Goodf("New scanfile %s created\n", fileName)
}

func uploadProject(c *client.C, project *lair.Project) {
	res, err := c.ImportProject(&client.DOptions{ForcePorts: false, LimitHosts: false}, project)
	if err != nil {
		print.Badf("Fatal: Unable to import project. Error %s", err.Error())
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		print.Badf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		print.Badf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		print.Badf("Fatal: Import failed. Error %s", droneRes.Message)
	}

}

func makeProjectBlue(previous *lair.Project) {
	// Turn issues blue if they are grey
	for x, issue := range previous.Issues {
		debugWriter("Checking on %s\n", issue.Title)
		if issue.Status != lair.StatusBlue || issue.Status != lair.StatusGreen {
			print.Goodf("Setting Issue %s to %s\n", issue.Title, lair.StatusBlue)
			previous.Issues[x].Status = lair.StatusBlue
		}
	}
	// Turn hosts blue if they are grey, also turn any service that was grey blue
	for i, host := range previous.Hosts {
		debugWriter("Checking on %s\n", host.IPv4)
		if host.Status != lair.StatusBlue || host.Status != lair.StatusGreen {
			print.Goodf("Setting host %s to %s\n", host.IPv4, lair.StatusBlue)
			previous.Hosts[i].Status = lair.StatusBlue
		}
		for j, service := range host.Services {
			debugWriter("Checking on %d\n", service.Port)
			if service.Status != lair.StatusBlue || service.Status != lair.StatusGreen {
				print.Goodf("Setting service %d to %s\n", service.Port, lair.StatusBlue)
				previous.Hosts[i].Services[j].Status = lair.StatusBlue
			}
		}
	}
}

func sameVulnNewHostCheck(previous lair.Project, nessusData *nessus.NessusData) {
	debugWriter("Making hashmap of new vulnerabilities\n")
	/*
		Loop over the new nessus data and make a map that has the name of the
		vulnerability as the key and the hosts affected as the value
	*/
	for _, host := range nessusData.Report.ReportHosts {
		for i, reportItem := range host.ReportItems {
			for _, previousIssue := range previous.Issues {
				if previousIssue.Title == reportItem.PluginName {
					for _, previousHost := range previousIssue.Hosts {
						if previousHost.IPv4 == host.Name {
							print.Goodf("Removing %s from %s\n", host.Name, reportItem.PluginName)
							host.ReportItems[i] = nessus.ReportItem{}
							break
						}
					}
					break
				}
			}
		}
	}
}

func isTop200Nmap(port nmap.Port) bool {
	x := port.PortId
	i := sort.Search(len(top200ports), func(i int) bool { return top200ports[i] >= x })
	if i < len(top200ports) && top200ports[i] == x && port.State.State == "open" {
		return true
	}
	return false
}

func isTop200Lair(service lair.Service) bool {
	x := service.Port
	i := sort.Search(len(top200ports), func(i int) bool { return top200ports[i] >= x })
	if i < len(top200ports) && top200ports[i] == x {
		return true
	}
	return false
}

func portCheck(previous *lair.Project, nmapData *nmap.NmapRun) recolor {
	/*
		Making a map of previous hosts with a slice of top 200 ports
	*/
	reco := recolor{}
	reco.service = make(map[string][]int)
	previousHostTopPorts := make(map[string][]int)
	previousHostAllPorts := make(map[string][]int)
	for _, previousHost := range previous.Hosts {
		uniquePorts := make(map[int]struct{})
		for _, previousService := range previousHost.Services {
			if isTop200Lair(previousService) {
				uniquePorts[previousService.Port] = struct{}{}
			}
			previousHostAllPorts[previousHost.IPv4] = append(previousHostAllPorts[previousHost.IPv4], previousService.Port)
		}
		for port := range uniquePorts {
			previousHostTopPorts[previousHost.IPv4] = append(previousHostTopPorts[previousHost.IPv4], port)
		}
	}
	for _, ports := range previousHostAllPorts {
		sort.Ints(ports)
	}
	for _, ports := range previousHostTopPorts {
		sort.Ints(ports)
	}
	debugWriter("All Ports: %v\n", previousHostAllPorts)
	debugWriter("Top Ports: %v\n", previousHostTopPorts)
	for i, host := range nmapData.Hosts {
		newTop200 := []int{}
		for _, port := range host.Ports {
			if isTop200Nmap(port) {
				newTop200 = append(newTop200, port.PortId)
			}
		}
		foundNewPort := false
		// Top 200 Port check
		for _, address := range host.Addresses {
			if oldPorts, ok := previousHostTopPorts[address.Addr]; ok {
				for _, newPort := range newTop200 {
					portIndex := sort.SearchInts(oldPorts, newPort)
					if len(oldPorts) == portIndex {
						print.Goodf("Host %s had a new top 200 port %d\n", address.Addr, newPort)
						foundNewPort = true
						break
					}
				}
				if foundNewPort == true {
				}
			} else {
				foundNewPort = true
			}
			if oldAllPorts, ok := previousHostAllPorts[address.Addr]; ok {
				debugWriter("OLD %s with ports %v\n", address.Addr, oldAllPorts)
				debugWriter("NEW %s with ports %v\n", address.Addr, host.Ports)
				reco.service[address.Addr] = append(reco.service[address.Addr], oldAllPorts...)
				for _, newPort := range host.Ports {
					if newPort.State.State != "open" {
						continue
					}
					portIndex := sort.SearchInts(oldAllPorts, newPort.PortId)
					if len(oldAllPorts) == portIndex && foundNewPort == false {
						print.Goodf("Host %s had a new port %d\n", address.Addr, newPort.PortId)
						foundNewPort = true
						reco.hosts = append(reco.hosts, address.Addr)
						break
					}

				}
			}
		}
		if !foundNewPort {
			debugWriter("Removing host %s\n", host.Addresses[0].Addr)
			nmapData.Hosts[i] = nmap.Host{}
		}
	}
	return reco
}
