package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	tls "github.com/piligo/gmtls"

	slog "github.com/cihub/seelog"
)

var (
	ServerIP = flag.String("server", ":43330", "server: ip:port")
	PemDir   = flag.String("certsdir", "./certs", "client is true,srv is false")
	Debug    = flag.Bool("debug", false, "open debug log is true")
)

func initLoger(filename string, isdebug bool) {
	logConfig := `
    <seelog>
    <outputs formatid="main">
        <filter levels="debug,info,error,warn">
                 <rollingfile type="date" filename="LOGNAME" datepattern="2006-01-02" namemode="prefix" maxrolls="180"/>
        </filter>
       <filter levels="info,error,warn">
                <console />
       </filter>
    </outputs>
    <formats>
        <format id="main" format="%Date(2006-01-02 15:04:05.999) [%File:%Line][%FuncShort][%Level] %Msg%n"/>
    </formats>
    </seelog>
    `
	logConfig = strings.Replace(logConfig, "LOGNAME", filename, -1)
	if !isdebug {
		//非debug
		logConfig = strings.Replace(logConfig, "debug,", "", -1)
	}
	logger, err := slog.LoggerFromConfigAsString(logConfig)
	if err != nil {
		panic(err)
	}
	slog.ReplaceLogger(logger)
}

func loadCerts(pemdir string) ([]tls.Certificate, error) {
	cerfiles := []string{"SS", "CA", "SE"}
	certs := make([]tls.Certificate, 0)
	for _, n := range cerfiles {
		certname := fmt.Sprintf("%s/%s.cert.pem", pemdir, n)
		certkey := fmt.Sprintf("%s/%s.key.pem", pemdir, n)
		cer, err := tls.LoadX509KeyPair(certname, certkey)
		if err != nil {
			slog.Error("tls.LoadX509KeyPair err->", err, " name=", certname, " key=", certkey)
			return nil, err
		}
		certs = append(certs, cer)
	}
	return certs, nil

}

func gmserver_echo(serverip string, pemdir string) {
	slog.Info(" server start ")
	cers, err := loadCerts(pemdir)
	if err != nil {
		slog.Error("server_echo : loadCerts err->", err)
		return
	}
	config := &tls.Config{Certificates: cers}
	ln, err := tls.Listen("tcp", serverip, config)
	if err != nil {
		slog.Error("server_echo : Listen err->", err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		slog.Info("\n\n======================= 国密服务端 等待 接收数据(\\n 结尾))=============================")
		msg, err := r.ReadString('\n')
		if err != nil {
			slog.Error("handleConnection ReadString err->", err)
			return
		}
		slog.Info("Server: RECV MSG->[", msg+"]")
		slog.Info("Server: start Send")
		n, err := conn.Write([]byte("SERVER RESP:" + msg + "\n"))
		if err != nil {
			slog.Error("handleConnection Write err->", n, err)
			return
		}
		slog.Info("Server: Send Ok")
	}

}

func main() {
	flag.Parse()
	defer slog.Flush()
	fmt.Println("---------------- 国密server ------------------")
	fmt.Println("gmserver_listen:", *ServerIP)
	serverlog := "gmserver.log"
	initLoger(serverlog, *Debug)
	gmserver_echo(*ServerIP, *PemDir)
}
