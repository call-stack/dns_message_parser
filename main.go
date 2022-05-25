package main

import (
	"encoding/hex"
	"fmt"
	"net"
)

type MessageBuffer struct {
	buf      []byte
	currPos  int
	bufLen   int
	queryPos int
}

const BufferOverflowError = "Size of currpos is greater than buffer size"

func (m *MessageBuffer) ReadSingleByte() (int8, error) {
	if m.currPos >= m.bufLen {
		return 0, fmt.Errorf(BufferOverflowError)
	}
	res := m.buf[m.currPos]
	m.currPos++
	return int8(res), nil
}

func (m *MessageBuffer) ReadTwoByte() (uint16, error) {
	if m.currPos+1 >= m.bufLen {
		return 0, fmt.Errorf(BufferOverflowError)
	}

	res := (uint16(m.buf[m.currPos]) << 8) | uint16(m.buf[m.currPos+1])
	m.currPos += 2
	return res, nil
}
func (m *MessageBuffer) ReadFourByte() (uint32, error) {
	if m.currPos+3 >= m.bufLen {
		return 0, fmt.Errorf(BufferOverflowError)
	}
	res := (uint32(m.buf[m.currPos]) << 24) | (uint32(m.buf[m.currPos+1]) << 16) | (uint32(m.buf[m.currPos+2]) << 8) | uint32(m.buf[m.currPos+3])
	m.currPos += 4
	return res, nil
}

func (m *MessageBuffer) getByte(pos int) uint8 {
	if pos > m.bufLen {
		return 0
	}
	return m.buf[pos]

}

func readName(buffer *MessageBuffer) string {

	cPos := buffer.currPos

	domainName := ""
	delimiter := ""
	isPointer := false
	for {
		value := buffer.getByte(cPos)
		if (value & 0xC0) == 0xC0 {

			if isPointer == false {
				buffer.currPos = cPos + 2
			}
			isPointer = true
			secondOctate := buffer.getByte(cPos + 1)
			offset := (uint16(value^0xC0))<<8 | uint16(secondOctate) //since pointer is combination of 2 octate and first 2 bits are represented that a jump is needed
			cPos = int(offset)
		} else {
			cPos++

			if value == 0 {
				break
			}
			var i uint8
			domainName += delimiter

			for i = 0; i < value; i++ {
				domainName += string(rune(int(buffer.getByte(cPos))))
				cPos++
			}

			delimiter = "."

		}
	}

	if isPointer == false {
		buffer.currPos = cPos
	}

	return domainName
}

type DNSHeader struct {
	ID                  uint16
	QueryResponse       bool
	OPCode              string
	AuthoritativeAnswer bool
	TruncatedAnswer     bool
	RecursionDesired    bool
	RecursionAvailable  bool
	ReservedAvailable   bool
	Reserved            int8
	ResponseCode        int8
	QuestionCount       uint16
	AnswerCount         uint16
	AuthorityCount      uint16
	AdditionCount       uint16
}

const (
	NOERROR  = "NOERROR"
	FORMERR  = "FORMERR"
	SERVFAIL = "SERVFAIL"
	NXDOMAIN = "NXDOMAIN"
	NOTIMP   = "NOTIMP"
	REFUSED  = "REFUSED"
)

func getErrorFromNums(num int8) string {
	switch num {
	case 0:
		return NOERROR
	case 1:
		return FORMERR
	case 2:
		return SERVFAIL
	case 3:
		return NXDOMAIN
	case 4:
		return NOTIMP
	case 5:
		return REFUSED
	default:
		return NOERROR
	}
}

func (d *DNSHeader) readHeader(buffer *MessageBuffer) {
	d.ID, _ = buffer.ReadTwoByte()
	//fmt.Println(d.ID, buffer.currPos)
	flags, _ := buffer.ReadTwoByte()
	firstPart, secondPart := (flags >> 8), (flags & 0xFF)
	if (firstPart & (1 << 7)) > 0 {
		d.QueryResponse = true
	} else {
		d.QueryResponse = false
	}

	OPCode := uint8((firstPart >> 3) & 0x0F)
	d.OPCode = getOpCodeTypeFromNum(OPCode)

	if (firstPart & (1 << 2)) > 0 {
		d.AuthoritativeAnswer = true
	}

	if (firstPart & (1 << 1)) > 0 {
		d.TruncatedAnswer = true
	}

	if (firstPart & 1) > 0 {
		d.RecursionDesired = true
	}

	if (secondPart & (1 << 7)) > 0 {
		d.RecursionAvailable = true
	}

	d.Reserved = int8((secondPart >> 4) & 0x07)
	d.ResponseCode = int8(secondPart & 0x0F)

	d.QuestionCount, _ = buffer.ReadTwoByte()
	d.AnswerCount, _ = buffer.ReadTwoByte()
	d.AuthorityCount, _ = buffer.ReadTwoByte()
	d.AdditionCount, _ = buffer.ReadTwoByte()

}

type DNSQuestion struct {
	Name  string
	Type  string
	Class string
}

func (q *DNSQuestion) Read(buffer *MessageBuffer) {
	q.Name = readName(buffer)
	qtype, _ := buffer.ReadTwoByte()
	q.Type = getQueryTypeFromNum(qtype)
	q.Class = "IN" // by default it is generally 1
	buffer.currPos += 2
}

type Record struct {
	Name      string
	Type      string
	Class     string
	TTL       uint32
	Len       uint16
	IPAddress net.IP
	cname     string
	IPv6      string
}

func (a *Record) Read(buffer *MessageBuffer) {
	a.Name = readName(buffer)

	qType, _ := buffer.ReadTwoByte()
	a.Type = getQueryTypeFromNum(qType)
	buffer.currPos += 2
	a.Class = "IN"
	a.TTL, _ = buffer.ReadFourByte()
	a.Len, _ = buffer.ReadTwoByte()

	switch a.Type {
	case A:
		rawIpAddress, _ := buffer.ReadFourByte()
		ipAddress := net.IPv4(byte(rawIpAddress>>24&0xFF), byte(rawIpAddress>>16&0xFF), byte(rawIpAddress>>8&0xFF), byte(rawIpAddress&0xFF))
		a.IPAddress = ipAddress
	case CNAME:
		domainName := readName(buffer)
		a.cname = domainName

	case AAAA:
		part1, _ := buffer.ReadTwoByte()
		part2, _ := buffer.ReadTwoByte()
		part3, _ := buffer.ReadTwoByte()
		part4, _ := buffer.ReadTwoByte()
		part5, _ := buffer.ReadTwoByte()
		part6, _ := buffer.ReadTwoByte()
		part7, _ := buffer.ReadTwoByte()
		part8, _ := buffer.ReadTwoByte()

		ipv6 := fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", part1, part2, part3, part4, part5, part6, part7, part8)

		a.IPv6 = fmt.Sprintf("%v", net.ParseIP(ipv6))

	}

}

const (
	A       = "A"
	CNAME   = "CNAME"
	AAAA    = "AAAA"
	UNKNOWN = "UNKNOWN"
)

func getQueryTypeFromNum(qType uint16) string {
	switch qType {
	case 1:
		return A
	case 5:
		return CNAME
	case 28:
		return AAAA
	default:
		return UNKNOWN

	}
}

const (
	QUERY  = "QUERY"
	IQUERY = "IQUERY"
	STATUS = "STATUS"
)

func getOpCodeTypeFromNum(code uint8) string {
	switch code {
	case 0:
		return QUERY
	case 1:
		return IQUERY
	case 2:
		return STATUS
	default:
		return "FUTURE USE"

	}
}

type DNSMessage struct {
	Header      DNSHeader
	Question    []DNSQuestion
	Answer      []Record
	Authorities []Record
	Additional  []Record
}

func (d *DNSMessage) Read(buffer *MessageBuffer) {
	d.Header.readHeader(buffer)
	var i uint16
	for i = 0; i < d.Header.QuestionCount; i++ {
		ques := DNSQuestion{}
		ques.Read(buffer)
		d.Question = append(d.Question, ques)
	}

	for i = 0; i < d.Header.AnswerCount; i++ {
		record := Record{}
		record.Read(buffer)

		d.Answer = append(d.Answer, record)
	}
	for i = 0; i < d.Header.AuthorityCount; i++ {
		record := Record{}
		record.Read(buffer)
		d.Authorities = append(d.Authorities, record)
	}
	for i = 0; i < d.Header.AdditionCount; i++ {
		record := Record{}
		record.Read(buffer)
		d.Additional = append(d.Additional, record)
	}
}

func main() {

	//var dnsMessage string
	//fmt.Scanln(&dnsMessage)

	dnsMessage := "762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019"
	data, _ := hex.DecodeString(dnsMessage)

	messageBuffer := &MessageBuffer{data, 0, len(data), 0}
	dnsHeader := DNSHeader{}
	dns := DNSMessage{dnsHeader, make([]DNSQuestion, 0), make([]Record, 0), make([]Record, 0), make([]Record, 0)}
	dns.Read(messageBuffer)
	fmt.Printf(";; ->>HEADER<<- opcode: %v, status: %v, id: %v\n", dns.Header.OPCode, getErrorFromNums(dns.Header.ResponseCode), dns.Header.ID)

	flagsSet := ""
	if dns.Header.QueryResponse {
		flagsSet += "qr"
	}
	if dns.Header.AuthoritativeAnswer {
		flagsSet += " aa"
	}
	if dns.Header.TruncatedAnswer {
		flagsSet += " tc"
	}
	if dns.Header.RecursionDesired {
		flagsSet += " rd"
	}
	if dns.Header.RecursionAvailable {
		flagsSet += " ra"
	}

	fmt.Printf(";; flags: %v; QUERY: %v, ANSWER: %v, AUTHORITY: %v, ADDITIONAL: %v \n", flagsSet, dns.Header.QuestionCount, dns.Header.AnswerCount, dns.Header.AuthorityCount, dns.Header.AdditionCount)
	fmt.Println()
	fmt.Println(";; QUESTION SECTION:")
	for _, q := range dns.Question {
		fmt.Printf(";%v.\t\tIN\t%v\n", q.Name, q.Type)
	}
	fmt.Println()
	fmt.Println(";; ANSWER SECTION:")
	for _, a := range dns.Answer {
		if a.Type == CNAME {
			fmt.Printf("%v.\t\t%v\tIN\t%v\t%v.\n", a.Name, a.TTL, a.Type, a.cname)
			continue
		} else if a.Type == AAAA {
			fmt.Printf("%v.\t\t%v\tIN\t%v\t%v\n", a.Name, a.TTL, a.Type, a.IPv6)
			continue
		}
		fmt.Printf("%v.\t\t%v\tIN\t%v\t%v\n", a.Name, a.TTL, a.Type, a.IPAddress)
	}

	////fmt.Println(";; AUTHORITY SECTION:")
	////for _, a := range dns.Answer {
	////   fmt.Printf("%v.\t\t%v\tIN\t%v\t%v\n", a.Name, a.TTL, a.Type, a.IPAddress)
	////}

}
