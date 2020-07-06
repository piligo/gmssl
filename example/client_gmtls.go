package main

import (
	"os"

	tls "github.com/piligo/gmtls"

	"bufio"
	"flag"
	"fmt"
	"strings"
	"time"

	slog "github.com/cihub/seelog"
)

var (
	ServerIP = flag.String("server", ":44330", "server: ip:port")
	Debug    = flag.Bool("debug", true, "open debug log is true")
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

//客户端
func gmclient_echo(serverip string) {

	conf := &tls.Config{
		InsecureSkipVerify: true, //为true 接收任何服务端的证书不做校验
	}
	conn, err := tls.Dial("tcp", serverip, conf)
	if err != nil {
		slog.Info("Dial ERR->", err)
		return
	}
	slog.Info("Client: 国密连接服务器成功->", serverip)
	defer slog.Info("---------------END ----------------------------")
	defer time.Sleep(2 * time.Second)
	defer conn.Close()

	inputReader := bufio.NewReader(os.Stdin)
	r := bufio.NewReader(conn)
	for {
		slog.Info("Client: 请输入需要发送的字符串数据->")
		input, err := inputReader.ReadString('\n')
		if err != nil {
			slog.Error("scaner err->", err)
			return
		}
		if input == "END\n" {
			slog.Info("END DEAL")
			return
		}

		slog.Info("============= 开始发送数据 ==============")
		slog.Info("Client: Send Data->[", input, "]")
		n, err := conn.Write([]byte(input))
		if err != nil {
			slog.Info(n, err)
			return
		}
		slog.Info("============= 开始接收服务端数据 ==============")
		msg, err := r.ReadString('\n')
		if err != nil {
			slog.Error("handleConnection ReadString err->", err)
			return
		}
		slog.Info("Client: RECV MSG->[", msg+"]")

	}
}

func main() {
	flag.Parse()
	defer slog.Flush()
	fmt.Println("---------------- 国密 client ------------------")
	fmt.Println("server_address:", *ServerIP)
	clientlog := "gmclient.log"
	initLoger(clientlog, *Debug)
	gmclient_echo(*ServerIP)

}
