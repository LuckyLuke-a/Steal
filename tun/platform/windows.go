//go:build windows

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"steal/vars"
	"strings"
	"syscall"
	"time"

	"steal/tun/tun2socks/engine"

	"github.com/jackpal/gateway"
	"golang.org/x/sys/windows"
)

type TunHandler struct {
	firewallRouteName string
	assignedTunIP string
	serverAddr string
	isRunning bool
}

func (t *TunHandler) init(){
	t.assignedTunIP = "192.168.123.1"
	t.firewallRouteName = "StealClient Block UDP DNS on Default Interface"
}
// Start tun mode in windows
func (t *TunHandler) Start() error {
	if vars.LoadedConfig.DebugMode {
		if !isAdmin() {
			runAsAdmin()
			time.Sleep(time.Second * 10)
			os.Exit(0)
		}
	} else {
		if !isAdmin() {
			return errors.New("tun mode need run as administrator")
		}
	}

	selectFirstInbound := vars.LoadedConfig.Inbounds[0]
	interfaceName := vars.LoadedConfig.TunMode.Name

	serverAddr := strings.Split(vars.LoadedConfig.Outbounds[0].Addr, ":")
	t.serverAddr = 	serverAddr[0]


	defaultInterfaceName, err := getDefaultInterface()
	if err != nil {
		return err
	}
	networkGatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}



	// Start tun2socks engine
	key := engine.Key{
		MTU:       vars.LoadedConfig.TunMode.MTU,
		Device:    interfaceName,
		LogLevel:  "error",
		Proxy:     fmt.Sprintf("%s://%s", selectFirstInbound.Protocol, selectFirstInbound.Addr),
	}
	engine.Insert(&key)
	if err := engine.Start(); err != nil{
		return err
	}	
	t.isRunning = true


	// Clear old route, if exist
	t.clearRouting()


	// Assign ip to created tun interface
	command := fmt.Sprintf(`/c netsh interface ipv4 set address name="%s" source=static addr=%s mask=255.255.255.0`, interfaceName, t.assignedTunIP)
	if err := t.runCommand(command, true); err != nil {
		return err
	}

	// Assign dns to created tun interface
	command = fmt.Sprintf(`/c netsh interface ipv4 set dnsservers name="%s" static address=%s register=none validate=no`, interfaceName, defaultDnsResolverService)
	if err := t.runCommand(command, true); err != nil {
		return err
	}

	// Route only server_ip to default network interface
	command = fmt.Sprintf(`/c route add %s mask 255.255.255.255 %s metric 1`, t.serverAddr, networkGatewayIP.String())
	if err := t.runCommand(command, true); err != nil {
		return err
	}

	// Route all traffic to tun interface, (except server_ip, to avoid loopback problem)
	command = fmt.Sprintf(`/c netsh interface ipv4 add route 0.0.0.0/0 "%s" %s metric=1`, interfaceName, t.assignedTunIP)
	if err := t.runCommand(command, true); err != nil {
		return err
	}

	// Flush windows dns cache
	command = "ipconfig /flushdns"
	if err := t.runCommand(command, false); err != nil {
		return err
	}

	// Prevent dns leak
	command = fmt.Sprintf(`New-NetFirewallRule -DisplayName "%s" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Block -InterfaceAlias "%s"`, t.firewallRouteName, defaultInterfaceName)
	if err := t.runPowershell(command); err != nil {
		return err
	}
	return nil

}

func (t *TunHandler) Stop() error {
	t.clearRouting()
	if t.isRunning{
		if err := engine.Stop(); err != nil{
			return err
		}	
	}
	return nil
}



func (t *TunHandler) runCommand(command string, waitToFinish bool) error {
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: command}
	var err error
	if waitToFinish{
		err = cmd.Run()
	}else{
		err = cmd.Start()
	}

	if err != nil {
		return err
	}

	return nil
}


func (t *TunHandler) runPowershell(command string) error {
    cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", command)
    if err := cmd.Run(); err != nil {
        return err
    }
    return nil
}




// Clear tun routing before start or stop app
func (t *TunHandler) clearRouting(){
	t.init()
	command := fmt.Sprintf(`/c route delete 0.0.0.0 mask 0.0.0.0 %s`, t.assignedTunIP)
	t.runCommand(command, true)

	deleteRoute := false
	serverAddrIP := net.ParseIP(t.serverAddr)
	if serverAddrIP != nil && !serverAddrIP.IsPrivate(){
		deleteRoute = true
	}
	if deleteRoute{
		command = fmt.Sprintf(`/c route delete %s`, t.serverAddr)
		t.runCommand(command, true)		
	}

	command = fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s"`, t.firewallRouteName)
	t.runPowershell(command)

}

// Found default primary network interface name
func getDefaultInterface() (string, error) {
	interfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		return "", err
	}
	stringIP := interfaceIP.String()
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, adder := range addrs {
			netIP, _, _ := net.ParseCIDR(adder.String())
			ifaceIP := netIP.String()
			if strings.EqualFold(ifaceIP, stringIP) {
				return iface.Name, nil
			}
		}
	}
	return "", errors.New("can not find default interface name")

}

// Run proccess as admin (only used in debugMode)
func runAsAdmin() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

// Check the current runned proccess is admin or not (only used in debugMode)
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}
