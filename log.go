package main


import "fmt"
import "log"
import "os"
import "regexp"
import "strings"
import "golang.org/x/exp/inotify"

const ANSI_COLOR_RED =		"\033[0;31m"
const ANSI_COLOR_RED_BOLD =	"\033[1;31m"
const ANSI_COLOR_RESET =	"\033[0m"


const AUDIT_LOG_FILE = "/var/log/audit/audit.log"

const BUFSIZE = 4096

type LogFilter struct {
	Regexp string 
	Fields []string
	OutputStr string
	OutputAttr string
	Regcomp *regexp.Regexp
}

type LogAuditFile struct {
	Desc string
	PathName string
	Filters []LogFilter
	f *os.File
}

var ( AuditLogs  = []LogAuditFile {
/*0*/	{ Desc: "auditd events",	PathName: "/var/log/audit/audit.log", Filters: []LogFilter{
		{ Regexp: "^type=SECCOMP msg=.+exe=\"(?P<exename>.+)\".+arch=(?P<arch>.+) syscall=(?P<syscall>[0-9]+)",
			Fields: []string{ "exename", "arch", "syscall" },
			OutputStr: "SECCOMP violation detected when application {exename} attempted to call syscall no. {syscall}",
			OutputAttr: ANSI_COLOR_RED_BOLD },
		{ Regexp: "^type=AVC.+apparmor=\"DENIED\" operation=\"(?P<operation>.+?)\".+profile=\"(?P<profile>.+?)\".+name=\"(?P<target>.+?)\".+comm=\"(?P<application>.+?)\".+",
			Fields: []string{ "operation", "application", "target" },
			OutputStr: "AppArmor violation of profile {profile} detected from {application} attempting {operation} on {target}",
			OutputAttr: ANSI_COLOR_RED_BOLD } } },
/*1*/	{ Desc: "oz daemon log",	PathName: "/var/log/oz-daemon.log", Filters: []LogFilter{
		{ Regexp: ".+oz-daemon\\[.+\\[(?P<application>.+)\\].+\\[FATAL\\] (?P<errmsg>.+)",
			Fields: []string{ "application", "errmsg" },
			OutputStr: "Fatal oz-daemon condition encountered in {application}: {errmsg}",
			OutputAttr: ANSI_COLOR_RED_BOLD } } },
/*2*/	{ Desc: "tor daemon log",	PathName: "/var/log/tor/log", Filters: []LogFilter{
		{ Regexp: ".+behind the time published.+\\((?P<utctime>.+)\\).+Tor needs an accurate clock.+Please check your time.+",
			Fields: []string{ "utctime" },
			OutputStr: "FATAL: TOR will not work unless you update your system clock to: {utctime}",
			OutputAttr: ANSI_COLOR_RED_BOLD },
		{ Regexp: ".+\\[warn\\] (?P<warning>.+)",
			Fields: []string{ "warning" },
			OutputStr: "TOR WARNING: {warning}",
			OutputAttr: ANSI_COLOR_RED } } },
/*3*/	{ Desc: "kernel and dmesg buffer",	PathName: "/var/log/kern.log", Filters: []LogFilter{
		{ Regexp: ".+kernel:.+PAX: terminating task: (?P<application>.+):[0-9]+,.+",
			Fields: []string{ "application" },
			OutputStr: "PAX terminated process: {application}",
			OutputAttr: ANSI_COLOR_RED_BOLD } } } }
)


func testRegexp(logIndex int, filterIndex int, expression string) {

	restr := AuditLogs[logIndex].Filters[filterIndex].Regexp;
	re := regexp.MustCompile(restr)

	fmt.Println("REGEXP: ", restr)
	fmt.Println("Being matched against: ", expression)

	match := re.FindStringSubmatch(expression)
	fmt.Println("match = ", match)
	fmt.Printf("XXX: %q\n", re.SubexpNames())

	rmap := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 {
			rmap[name] = match[i]
		}
	}

	for i := 0; i < len(AuditLogs[logIndex].Filters[filterIndex].Fields); i++ {
		fstr := AuditLogs[logIndex].Filters[filterIndex].Fields[i]
		fmt.Printf("Extracting field: %s = \"%s\"\n", fstr, rmap[fstr])
	}

	outstr := formatOutput(AuditLogs[logIndex].Filters[filterIndex].OutputStr, rmap)

	if len(outstr) == 0 {
		fmt.Println("*** No output string was returned.")
	} else {

		if len(AuditLogs[logIndex].Filters[filterIndex].OutputAttr) > 0 {
			outstr = AuditLogs[logIndex].Filters[filterIndex].OutputAttr + outstr + ANSI_COLOR_RESET
		}

		fmt.Println("OUTPUT: ", outstr)
	}

}

func formatOutput(src string, strMap map[string]string) (string) {
	retstr := src

	for key, val := range strMap {
//		fmt.Printf("range key = %s, val = %s, map[val] = %s\n", key, val, strMap[key])
		replStr := "{" + key + "}"
//		fmt.Println("SEARCHING FOR: ", replStr)
		retstr = strings.Replace(retstr, replStr, val, -1)
	}

	return retstr
}




func main() {


/*	
	fmt.Println("Attempting test...")
	testRegexp(1, 0, "Jul 18 17:44:52 subgraph oz-daemon[1273]: 2016/07/18 17:44:52 [ricochet] (stderr) E [FATAL] Error (exec): no such file or directory /usr/bin-oz/ricochet")
	fmt.Println("Exiting.")
	os.Exit(0) 
*/
	

	if os.Getuid() > 0 {
		fmt.Println("Warning: this program probably won't run unless you execute it as root.")
	}



	for i := 0; i < len(AuditLogs); i++ {
		f, err := os.OpenFile(AuditLogs[i].PathName, os.O_RDONLY, 0666)

		if err != nil {
			log.Fatal("Error opening log file for ", AuditLogs[i].Desc, ": ", err)
		}

		fi, err := f.Stat()

		if err != nil {
			log.Fatal("Could not call stat on log file: ", err)
		}

		fmt.Printf("total log file size for %s  is %d\n", AuditLogs[i].PathName, fi.Size())

		ret, err := f.Seek(0, os.SEEK_END)

		if (ret != fi.Size()) {
			log.Fatal("Unexpected problem occurred when attempting to skip to end of log file")
		}

		AuditLogs[i].f = f

		for j := 0; j < len(AuditLogs[i].Filters); j++ {
			AuditLogs[i].Filters[j].Regcomp = regexp.MustCompile(AuditLogs[i].Filters[j].Regexp)
		}

	}

	watcher, err := inotify.NewWatcher()

	if err != nil {
		log.Fatal("Could not set up new watcher: ", err)
	}

	for i := 0; i < len(AuditLogs); i++ {
		fmt.Println("Adding inotify watcher for service:", AuditLogs[i].Desc)
//		err = watcher.Watch(AuditLogs[i].PathName)
		err = watcher.AddWatch(AuditLogs[i].PathName, inotify.IN_MODIFY)

		if err != nil {
			log.Fatal("Could not set up watcher on log file: ", err)
		}

	}

	fmt.Printf("Done now.\n")

	dbuf := make([]byte, BUFSIZE)

	for {

		select {
			case ev := <-watcher.Event:
//				fmt.Println("watcher event")
//				log.Println("event: ", ev)
//				fmt.Printf("mask was %x\n", ev.Mask)

				if (ev.Mask != inotify.IN_MODIFY) {
					fmt.Println("Received unexpected notification event type... ignoring.")
					continue
				}

				i := 0

				for i < len(AuditLogs) {

					if (AuditLogs[i].PathName == ev.Name) {
//						fmt.Printf("comparison: |%s| vs |%s|\n", ev.Name, AuditLogs[i].PathName)
						break
					}

					i++;
				}

				if i == len(AuditLogs) {
					log.Fatal("Unexpected error occurred: received inotify event for unknown filename \"", ev.Name, "\"")
				}

				os.Getuid()
				nread, err := AuditLogs[i].f.Read(dbuf)
				os.Getpid()

				if err != nil && nread != 0 {
					log.Fatal("Error reading new data from log file: ", err)
				}

				if nread == 0 {
//					log.Fatal("Reached end of log file... this should not have happened!")
					fmt.Printf("Reached EOF for %s; attempting to ignore.\n", AuditLogs[i].PathName)
					continue
				}

//				fmt.Printf("ended up reading %d bytes from log\n", nread)

				sbuf := string(dbuf[:nread])

				for j := 0; j < len(AuditLogs[i].Filters); j++ {
//					fmt.Printf("trying regex filter %d: %s\n", j, AuditLogs[i].Filters[j].Regexp)
//					fmt.Printf("AGAINST: %s\n", sbuf)

					match := AuditLogs[i].Filters[j].Regcomp.FindStringSubmatch(sbuf)

					if match == nil {
//						fmt.Printf("%sdid not match, continuing%s\n", ANSI_COLOR_RED_BOLD, ANSI_COLOR_RESET)
						continue
					}

					rmap := make(map[string]string)

					for k, name := range AuditLogs[i].Filters[j].Regcomp.SubexpNames() {

						if k != 0 {
							rmap[name] = match[k]
						}

					}

/*					for k := 0; k < len(AuditLogs[i].Filters[j].Fields); k++ {
						fstr := AuditLogs[i].Filters[j].Fields[k]
						fmt.Printf("Extracting field: %s = %s\n", fstr, rmap[fstr])
					} */

					outstr := formatOutput(AuditLogs[i].Filters[j].OutputStr, rmap)

				        if len(outstr) == 0 {
						fmt.Println("*** Filter condition was matched but no output string was generated")
					} else {

				                if len(AuditLogs[i].Filters[j].OutputAttr) > 0 {
							outstr = AuditLogs[i].Filters[j].OutputAttr + outstr + ANSI_COLOR_RESET
						}

						fmt.Println("OUTPUT: ", outstr)
					}

				}

			case err := <-watcher.Error:
				log.Println("error: ", err)
		}

	}

}
