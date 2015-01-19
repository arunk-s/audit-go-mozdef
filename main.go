package main

import (
	"./netlinkAudit"
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var done chan bool
var debug bool

type json_msg_type struct {
	category    string
	summary     string
	severity    string
	hostname    string
	processid   uint32
	processname string
	timestamp   string
	// may be ring buffer
}

func load_SysmapX64_i() (map[int]string, error) {
	// Loads syscalls into a map with key as their syscall numbers
	/*
	   0    read
	   1    write
	   2    open
	*/
	inFile, err := os.Open("netlinkAudit/sysmapx64")
	if err != nil {
		return nil, err
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	sysmap := make(map[int]string)
	for scanner.Scan() {
		vals := strings.Split(scanner.Text(), "\t")
		sno, err := strconv.Atoi(vals[0])
		if err == nil {
			sysmap[sno] = vals[1]
		}
	}
	return sysmap, nil
}

func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		log.Println(err)
		log.Fatalln("Error while availing socket! Exiting!")
	}
	defer s.Close()
	debug = false

	if os.Getuid() != 0 {
		log.Fatalln("Not Root User! Exiting!")
	}
	err = netlinkAudit.AuditSetEnabled(s)
	if err != nil {
		log.Fatal("Error while enabling Audit !", err)
	}
	err = netlinkAudit.AuditIsEnabled(s)

	if debug == true {
		log.Println(netlinkAudit.ParsedResult)
	}
	if err == nil && netlinkAudit.ParsedResult.Enabled == 1 {
		log.Println("Enabled Audit!!")
	} else {
		log.Fatalln("Audit Not Enabled! Exiting")
	}
	err = netlinkAudit.AuditSetRateLimit(s, 600)
	if err != nil {
		log.Fatalln("Error Setting Rate Limit!!", err)
	}
	err = netlinkAudit.AuditSetBacklogLimit(s, 420)
	if err != nil {
		log.Fatalln("Error Setting Backlog Limit!!", err)
	}
	err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))

	if err == nil {
		log.Println("Set pid successful!!")
	}
	err = netlinkAudit.SetRules(s)
	// err = netlinkAudit.DeleteAllRules(s)
	if err != nil {
		log.Fatalln("Setting Rules Unsuccessful! Exiting")
	}
	done := make(chan bool, 1)
	msg := make(chan string)
	errchan := make(chan error)
	f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		log.Fatalln("Error Creating File!!")
	}
	defer f.Close()
	// Load x64 map
	sysmap, err := load_SysmapX64_i()
	if err != nil {
		log.Fatalln("Error :", err)
	}

	go func() {
		for {
			select {
			case ev := <-msg:
				log.Println(ev + "\n")
				split := strings.Split(ev, " ")
				// Timestamp and serial num separation
				var timestamp string
				var serial string
				if len(split) > 0 {
					if len(split[1]) > 0 {
						ts := strings.Split(split[1], "(")
						if len(ts) == 2 {
							ts = strings.Split(ts[1], ")")
							timestampx := strings.Split(ts[0], ":")
							timestamp = timestampx[0]
							serial = timestampx[1]
							log.Println(timestamp, serial)
						}

					}
					//TODO Timestamp and event coordination
					data := split[2:]
					valmap := make(map[string]string)
					// valmap stores all the values with fieldnames as the key
					for i := 0; i < len(data); i++ {
						values := strings.Split(data[i], "=")
						if len(values) >= 2 {
							valmap[values[0]] = values[1]
						}
						// log.Println(values)
					}

					t_hostname, err := os.Hostname()
					if err != nil {
						t_hostname = "localhost"
						log.Printf("Cannot find Hostname, using %s as hostname", t_hostname)
					}

					var json_msg json_msg_type = json_msg_type{
						severity:  "INFO",
						hostname:  t_hostname,
						processid: 0,
					}
					timestamp_ := strings.Split(timestamp, ".")
					i := timestamp_[0]
					i_ := timestamp_[1]
					seconds, err := strconv.ParseInt(i, 10, 64)
					if err != nil {
						panic(err)
					}
					millis, err := strconv.ParseInt(i_, 10, 64)
					if err != nil {
						panic(err)
					}
					// log.Fatalln doesn't close resources

					tm := time.Unix((seconds), millis*1000000).String()
					json_msg.timestamp = tm

					if split[0] == "SYSCALL" {
						log.Println("For Syscall:", valmap["syscall"])
						sno, err := strconv.Atoi(valmap["syscall"])
						// Get syscall name, No arch detection, assuming 64 bits
						if err == nil {
							name := sysmap[sno]
							log.Println("Syscall", name)
						} else {
							log.Println(err)
						}
						// Way to store ?
						if valmap["comm"] != "" {
							json_msg.processname = valmap["comm"]
						}

					} else if split[0] == "CWD" {

					} else if split[0] == "PATH" {

					} else if split[0] == "EXECVE" {

					} else if split[0] == "AVC" {

					}
					log.Println(json_msg)

				}
				_, err := f.WriteString(ev + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}
			case ev := <-errchan:
				log.Println(ev)
			}
		}
	}()

	go netlinkAudit.Getreply(s, done, msg, errchan)

	time.Sleep(time.Second * 10)
	done <- true
	close(done)
	//Important point is that NLMSG_ERROR is also an acknowledgement from Kernel.
	//If the first 4 bytes of Data part are zero then it means the message is acknowledged
}
