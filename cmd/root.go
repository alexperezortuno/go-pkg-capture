package cmd

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type ExportType string

func (e ExportType) String() string {
	return string(e)
}

func (e *ExportType) Set(value string) {
	if value == "txt" || value == "pcap" {
		*e = ExportType(value)
	} else {
		*e = "txt"
	}
}

var (
	timeToCapture int
	deviceName    string
	exportType    string
	exportName    string
	exportPath    string
	showDevices   bool
	filter        string
	debug         bool
	help          bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-pkg-capture",
	Short: "Capture packets from a network interface",
	Long: `This application captures packets from a network interface and saves them to a file.
    Usage: go-pkg-capture [flags]

	Flags:
	-h, --help: Show help
	-t, --time: Time to capture packets
	-d, --device: Device to capture packets
	-e, --export: Type of export (txt, pcap)
	-n, --name: Name of the export file
	-p, --path: Path to save the export file
	-l, --devices: List all devices
	-f, --filter: Filter packets (e.g., tcp, udp)
	-x, --debug: Show debug information
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}

	if help {
		os.Exit(0)
	}

	var writer *pcapgo.Writer
	var fileType ExportType
	fileType.Set(exportType)

	if showDevices {
		// list all devices
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Devices found:")
		for _, device := range devices {
			fmt.Printf("Name: %s\n", device.Name)
			if len(device.Addresses) > 0 {
				for _, address := range device.Addresses {
					fmt.Printf("  IP address: %s\n", address.IP)
				}
			}
		}
		os.Exit(0)
	}

	// Open the device for packet capture
	handle, err := pcap.OpenLive(deviceName, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Filter packets (e.g., only TCP)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Capturing packets on", deviceName)

	// Create file to save the captured packets
	fileName := fmt.Sprintf("%s%s_%s.%s", exportPath, exportName, time.Now().Format("20060102_150405"), fileType.String())
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(file)

	// Write header to the file
	if fileType.String() == "pcap" {
		writer = pcapgo.NewWriter(file)
		if err := writer.WriteFileHeader(1600, handle.LinkType()); err != nil {
			log.Fatal("Error writing the header of the .pcap file:", err)
		}
	} else {
		// Write header to the file
		_, err = file.WriteString("Packages capture - " + time.Now().Format("2006-01-02 15:04:05") + "\n")
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create a channel to stop the capture after the specified duration
	stopChan := make(chan bool)

	// Goroutine to stop the capture after `timeToCapture` seconds
	go func() {
		time.Sleep(time.Duration(timeToCapture) * time.Second)
		stopChan <- true
	}()

	// Capture packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if debug {
		fmt.Printf("Capturando paquetes durante %d segundos...\n", timeToCapture)
	}

	for {
		select {
		case packet := <-packetSource.Packets():
			// Get the current time and packet content
			timestamp := time.Now().Format("2006-01-02 15:04:05")

			packetData := fmt.Sprintf("[%s] Captured packet: %s\n", timestamp, packet)

			if debug {
				// Print packet to console
				fmt.Print(packetData)
			}

			// Save packet to file
			if fileType.String() == "pcap" {
				err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					log.Fatal("Error writing the packet to the .pcap file:", err)
				}
			} else {
				_, err := file.WriteString(packetData)
				if err != nil {
					log.Fatal(err)
				}
			}

		case <-stopChan:
			// Exit the loop when the stop signal is received
			if debug {
				fmt.Println("Capture time completed. Finishing...")
			}
			return
		}
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-pkg-capture.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().IntVarP(&timeToCapture, "time", "t", 10, "Time to capture packets")
	rootCmd.Flags().StringVarP(&deviceName, "device", "d", "eth0", "Device to capture packets")
	rootCmd.Flags().StringVarP(&exportType, "export", "e", "", "Type of export (txt, pcap)")
	rootCmd.Flags().StringVarP(&exportName, "name", "n", "capture", "Name of the export file")
	rootCmd.Flags().StringVarP(&exportPath, "path", "p", "", "Path to save the export file")
	rootCmd.Flags().BoolVarP(&showDevices, "devices", "l", false, "List all devices")
	rootCmd.Flags().StringVarP(&filter, "filter", "f", "", "Filter packets (e.g., tcp, udp)")
	rootCmd.Flags().BoolVarP(&debug, "debug", "x", false, "Show debug information")
	rootCmd.Flags().BoolVarP(&help, "help", "h", false, "Show help")
}
