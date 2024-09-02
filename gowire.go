package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"

	"github.com/adubovikov/gowire/gowireshark"
)

type Config struct {
	pcapReadFile string
	buf          bytes.Buffer
}

var logger *log.Logger
var buf bytes.Buffer
var config Config

func main() {

	var (
		inputFilepath = flag.String("input-pcap-file", "./example/pcap/sip_ipv4_tcp.pcap", "Pcap file to read from")
	)
	flag.Parse()

	logger = log.New(&buf, "logger: ", log.Lshortfile)

	// err := gowireshark.DissectPrintAllFrame(*inputFilepath)
	// if err != nil {
	// 	logger.Println(err)
	// }

	res, err := gowireshark.GetAllFrameProtoTreeInJson(*inputFilepath, true, false)
	if err != nil {
		logger.Fatal(err)
	}

	for _, frameData := range res {
		colSrc := frameData.WsSource.Layers["_ws.col"]
		col, err := gowireshark.UnmarshalWsCol(colSrc)
		if err != nil {
			log.Fatal(err)
			fmt.Println("BAD packet:", err)
		}

		fmt.Println("# Frame index:", col.Num, "===========================")
		fmt.Println("## WsIndex:", frameData.WsIndex)
		fmt.Println("## Offset:", frameData.Offset)
		fmt.Println("## Hex:", frameData.Hex)
		fmt.Println("## Ascii:", frameData.Ascii)
	}

	// frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(*inputFilepath, 1, true, true)
	// if err != nil {
	// 	fmt.Println("BAD packet:", err)
	// }

	// colSrc := frameData.WsSource.Layers["_ws.col"]
	// col, err := gowireshark.UnmarshalWsCol(colSrc)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// frameSrc := frameData.WsSource.Layers["frame"]
	// frame, err := gowireshark.UnmarshalFrame(frameSrc)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// fmt.Println("# Frame index:", col.Num)
	// fmt.Println("## WsIndex:", frameData.WsIndex)
	// fmt.Println("## Offset:", frameData.Offset)
	// fmt.Println("## Hex:", frameData.Hex)
	// fmt.Println("## Ascii:", frameData.Ascii)

	// fmt.Println("【layer _ws.col】:", col)
	// fmt.Println("【layer frame】:", frame)
}
