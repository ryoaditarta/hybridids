// // filter.go: Fast matching & filtering Suricata eve.json and cicflowmeter CSV
// // Compile: go build -o filter filter.go
// // Usage: ./filter eve.json result.csv result_labeled.csv result_filtered.csv
// package main

// import (
//     "bufio"
//     "encoding/csv"
//     "encoding/json"
//     "fmt"
//     "os"
//     "strings"
//     "time"
// )

// type Alert struct {
//     Key   string
//     TS    time.Time
//     Label string
// }

// func tupleKey(srcIP, srcPort, dstIP, dstPort, proto string) string {
//     a := srcIP + ":" + srcPort
//     b := dstIP + ":" + dstPort
//     if a <= b {
//         return a + "-" + b + "-" + proto
//     }
//     return b + "-" + a + "-" + proto
// }

// func parseTime(ts string) (time.Time, error) {
//     if len(ts) >= 26 {
//         t, err := time.Parse("2006-01-02T15:04:05.000000", ts[:26])
//         if err == nil {
//             return t, nil
//         }
//     }
//     if len(ts) >= 19 {
//         t, err := time.Parse("2006-01-02 15:04:05", ts[:19])
//         if err == nil {
//             return t, nil
//         }
//     }
//     return time.Time{}, fmt.Errorf("invalid time: %s", ts)
// }

// func main() {
//     if len(os.Args) != 5 {
//         fmt.Fprintf(os.Stderr, "Usage: %s eve.json result.csv result_labeled.csv result_filtered.csv\n", os.Args[0])
//         os.Exit(1)
//     }
//     evePath := os.Args[1]
//     csvPath := os.Args[2]
//     labeledPath := os.Args[3]
//     filteredPath := os.Args[4]

//     sidLabel := map[string]string{"1004": "slowloris", "1005": "slowread", "1006": "slowpost"}
//     protoMap := map[string]string{"TCP": "6", "tcp": "6", "UDP": "17", "udp": "17", "ICMP": "1", "icmp": "1"}

//     // --- 1. Parse eve.json, build alert list ---
//     alerts := []Alert{}
//     eveFile, err := os.Open(evePath)
//     if err != nil {
//         fmt.Fprintf(os.Stderr, "[Go Filter] Gagal buka eve.json: %v\n", err)
//         os.Exit(1)
//     }
//     scanner := bufio.NewScanner(eveFile)
//     for scanner.Scan() {
//         var event map[string]interface{}
//         if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
//             continue
//         }
//         if event["event_type"] != "alert" {
//             continue
//         }
//         srcIP := fmt.Sprint(event["src_ip"])
//         srcPort := fmt.Sprint(event["src_port"])
//         dstIP := fmt.Sprint(event["dest_ip"])
//         dstPort := fmt.Sprint(event["dst_port"])
//         proto := fmt.Sprint(event["proto"])
//         sid := ""
//         if alert, ok := event["alert"].(map[string]interface{}); ok {
//             sid = fmt.Sprint(alert["signature_id"])
//         } else if s, ok := event["sid"]; ok {
//             sid = fmt.Sprint(s)
//         }
//         protoNum := protoMap[strings.ToUpper(proto)]
//         if protoNum == "" {
//             protoNum = proto
//         }
//         var start string
//         if flow, ok := event["flow"].(map[string]interface{}); ok {
//             if s, ok := flow["start"].(string); ok {
//                 start = s
//             }
//         }
//         if start == "" {
//             if s, ok := event["start"].(string); ok {
//                 start = s
//             }
//         }
//         t, err := parseTime(start)
//         if err != nil {
//             continue
//         }
//         key := tupleKey(srcIP, srcPort, dstIP, dstPort, protoNum)
//         label := sidLabel[sid]
//         alerts = append(alerts, Alert{key, t, label})
//     }
//     eveFile.Close()

//     // --- 2. Parse result.csv, build flows ---
//     csvFile, err := os.Open(csvPath)
//     if err != nil {
//         fmt.Fprintf(os.Stderr, "[Go Filter] Gagal buka result.csv: %v\n", err)
//         os.Exit(1)
//     }
//     reader := csv.NewReader(csvFile)
//     header, err := reader.Read()
//     if err != nil {
//         fmt.Fprintf(os.Stderr, "[Go Filter] Gagal baca header CSV: %v\n", err)
//         os.Exit(1)
//     }
//     flows := [][]string{}
//     for {
//         row, err := reader.Read()
//         if err != nil {
//             break
//         }
//         flows = append(flows, row)
//     }
//     csvFile.Close()

//     // --- 3. Matching & labeling ---
//     labelIdx := -1
//     for i, h := range header {
//         if h == "label" {
//             labelIdx = i
//             break
//         }
//     }
//     if labelIdx == -1 {
//         header = append(header, "label")
//         labelIdx = len(header) - 1
//     }
//     labeledRows := [][]string{header}
//     filteredRows := [][]string{header}

//     for _, row := range flows {
//         idx := func(name string) int {
//             for i, h := range header {
//                 if h == name {
//                     return i
//                 }
//             }
//             return -1
//         }
//         srcIP := row[idx("src_ip")]
//         srcPort := row[idx("src_port")]
//         dstIP := row[idx("dst_ip")]
//         dstPort := row[idx("dst_port")]
//         proto := row[idx("protocol")]
//         protoNum := protoMap[strings.ToUpper(proto)]
//         if protoNum == "" {
//             protoNum = proto
//         }
//         ts := row[idx("timestamp")]
//         t, _ := parseTime(ts)
//         key := tupleKey(srcIP, srcPort, dstIP, dstPort, protoNum)
//         label := ""
//         for _, alert := range alerts {
//             if alert.Key == key {
//                 dt := t.Sub(alert.TS)
//                 if dt < 0 {
//                     dt = -dt
//                 }
//                 if dt <= time.Second {
//                     label = alert.Label
//                     break
//                 }
//             }
//         }
//         outrow := make([]string, len(header))
//         copy(outrow, row)
//         if labelIdx >= len(outrow) {
//             outrow = append(outrow, label)
//         } else {
//             outrow[labelIdx] = label
//         }
//         labeledRows = append(labeledRows, outrow)
//         if label == "" {
//             filteredRows = append(filteredRows, outrow)
//         }
//     }

//     // --- 4. Write output files ---
//     out1, err := os.Create(labeledPath)
//     if err != nil {
//         fmt.Fprintf(os.Stderr, "[Go Filter] Gagal buat %s: %v\n", labeledPath, err)
//         os.Exit(1)
//     }
//     w1 := csv.NewWriter(out1)
//     for _, row := range labeledRows {
//         w1.Write(row)
//     }
//     w1.Flush()
//     out1.Close()

//     out2, err := os.Create(filteredPath)
//     if err != nil {
//         fmt.Fprintf(os.Stderr, "[Go Filter] Gagal buat %s: %v\n", filteredPath, err)
//         os.Exit(1)
//     }
//     w2 := csv.NewWriter(out2)
//     for _, row := range filteredRows {
//         w2.Write(row)
//     }
//     w2.Flush()
//     out2.Close()

//     fmt.Printf("[Go Filter] Selesai. Labeled: %d, Filtered: %d\n", len(labeledRows)-1, len(filteredRows)-1)
// }