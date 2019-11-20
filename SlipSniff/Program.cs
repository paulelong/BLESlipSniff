using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Ports;
using System.Collections;
using ETW;

namespace SlipSniff
{
    class Program
    {
        const byte SLIP_START = 0xAB;
        const byte SLIP_END = 0xBC;
        const byte SLIP_ESC = 0xCD;
        const byte SLIP_ESC_START = SLIP_START + 1;
        const byte SLIP_ESC_END = SLIP_END + 1;
        const byte SLIP_ESC_ESC = SLIP_ESC + 1;

        const byte HEADER_LENGTH = 0x6;
        const byte PROTOVER = 0x1;


        const byte REQ_FOLLOW = 0x00;
        const byte RESP_FOLLOW = 0x01;
        const byte EVENT_DEVICE = 0x02;
        const byte REQ_SINGLE_PACKET = 0x03;
        const byte RESP_SINGLE_PACKET = 0x04;
        const byte EVENT_CONNECT = 0x05;
        const byte REQ_SCAN_CONT = 0x7;
        const byte RESP_SCAN_CONT = 0x08;
        const byte EVENT_DISCONNECT = 0x09;
        const byte EVENT_ERROR = 0x0A;
        const byte EVENT_EMPTY_DATA_PACKET = 0x0B;
        const byte SET_TEMPORARY_KEY = 0x0C;
        const byte PING_REQ = 0x0D;
        const byte PING_RESP = 0x0E;
        const byte TEST_COMMAND_ID = 0x0F;
        const byte TEST_RESULT_ID = 0x10;
        const byte UART_TEST_START = 0x11;
        const byte UART_DUMMY_PACKET = 0x12;
        const byte SWITCH_BAUD_RATE_REQ = 0x13;
        const byte SWITCH_BAUD_RATE_RESP = 0x14;
        const byte UART_OUT_START = 0x15;
        const byte UART_OUT_STOP = 0x16;
        const byte SET_ADV_CHANNEL_HOP_SEQ = 0x17;
        const byte GO_IDLE = 0xFE;

        public struct slippacket
        {
            public bool read;
            public byte[] buf;
        }

        /*
ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]
*/
        private static SerialPort port;
        private static List<slippacket> capturebuf = new List<slippacket>();
        private static int totalbytes, totalframes, totalpackets;
        private static int counter = 0;

        [STAThread]
        static void Main(string[] args)
        {
            if(!ProcessArgs(args))
            {
                PrintCLIHelp();
            }
            else
            {
                // Default to COM8 because that's where my BLE sniffer is connected :)
                SerialPortProgram(args.Length > 0 ? args[0] : "COM8");
            }
        }

        private static void PrintCLIHelp()
        {
            Console.WriteLine("Usage is\n   {0} [comport]\ncomport is a string, default is COM8", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
        }

        private static bool ProcessArgs(string[] args)
        {
            // Since there are no args, just assume they are looking for help.
            if(args.Length > 0 && args[0][0] == '-')
            {
                return false;
            }

            return true;
        }

        private static void SerialPortProgram(string commstring)
        {
            port = new SerialPort(commstring, 460800, Parity.None, 8, StopBits.One);
            port.Handshake = Handshake.None;
            port.RtsEnable = true;

            Console.WriteLine("Incoming Data:");
            // Attach a method to be called when there
            // is data waiting in the port's buffer 
            port.DataReceived += new SerialDataReceivedEventHandler(port_DataReceived);
            //port.ReadTimeout = 10;

            try
            {
                // Begin communications 
                port.Open();

                SendPacket(GO_IDLE, null);

                // Enter an application loop to keep this thread alive 
                CmdMode();

                port.Close();

            }
            catch (Exception ex)
            {
                Console.Write(ex);
            }

            Console.WriteLine("Bye for now!");

        }

        static void ResetCapture()
        {
            capturebuf.Clear();
            totalbytes = 0;
            totalframes = 0;
            totalpackets = 0;
        }

        static void PrintCmdHelp()
        {
            Console.WriteLine("Commands don't require a newline.");
            Console.WriteLine(" Q - quit");
            Console.WriteLine(" C - Capture Packets");
            Console.WriteLine(" S - Stop the capture");
            Console.WriteLine(" D - Dump all the packets, only use when capture is stopped.");
            Console.WriteLine(" F - Prompt to type in an address to follow, type in like 1122AABB0099.");
            Console.WriteLine(" R - Report capture status");
        }

        static void CmdMode()
        {
            bool running = true;
            while(running)
            {
                ConsoleKeyInfo c = Console.ReadKey(true);
                switch (c.Key)
                {
                    case ConsoleKey.Q:
                        running = false;
                        break;
                    case ConsoleKey.R:
                        Console.WriteLine("TotalFrame: {0}, TotalBytes: {1}, TotalFrames: {2}", totalframes, totalbytes, totalpackets);
                        break;
                    case ConsoleKey.C:
                        capturebuf.Clear();
                        SendPacket(REQ_SCAN_CONT, null);
                        Console.WriteLine("Scan started");
                        break;
                    case ConsoleKey.S:
                        SendPacket(GO_IDLE, null);
                        Console.WriteLine("Scan stoppped");
                        break;
                    case ConsoleKey.D:
                        foreach (slippacket p in capturebuf)
                        {
                            Console.WriteLine(p.read ? "Read" : "Write");
                            if (p.buf != null)
                                dumpPacket(p.buf);
                        }
                        break;
                    case ConsoleKey.F:
                        Console.Write("Adr? ");
                        string adr = Console.ReadLine();
                        byte[] adrb = StringToByteArrayFastest(adr);
                        foreach(byte b in adrb)
                        {
                            Console.Write("{0} ", b);
                        }
                        Console.WriteLine("adr size {0}", adrb.Length);
                        SendPacket(REQ_FOLLOW, adrb);
                        break;
                    case ConsoleKey.Oem2:
                        if(c.KeyChar == '?')
                        {
                            PrintCmdHelp();
                        }
                        break;

                }
            }
        }

        public static byte[] StringToByteArrayFastest(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        private static void port_DataReceived(object sender, SerialDataReceivedEventArgs e)
        {
            SerialPort sp = (SerialPort)sender;

            int count = sp.BytesToRead;
            byte[] buf = new byte[count];
            sp.Read(buf, 0, count);
            List<byte> p = new List<byte>();

            totalframes++;
            totalbytes += count;

            int off = 0;
            while (off < buf.Length && buf[off++] != SLIP_START);

            while(off < buf.Length)
            {
                if(buf[off] == SLIP_END)
                {
                    //byte[] pkt = new byte[off - start];
                    //Buffer.BlockCopy(buf, start, pkt, 0, off - start);
                    //start = off + 1;
                    ReceivePacket(p.ToArray());
                    do
                    {
                        off++;
                    } while (off < buf.Length && buf[off] != SLIP_START) ;
                    p.Clear();
                }
                else if(buf[off] == SLIP_ESC)
                {
                    if(off < buf.Length - 1)
                        off++;
                    p.Add(buf[off]);
                }
                else
                {
                    p.Add(buf[off]);
                }

                off++;
            }
        }

        private static void ReceivePacket(byte[] payload)
        {
            CapturePacket(payload, true);
        }

        private static void CapturePacket(byte[] payload, bool read)
        {
            capturebuf.Add(new slippacket() { buf = payload, read = read });
            totalframes++;
            BLESniffRaw.EventWriteBLERawMessage((ushort)payload.Length, payload);
        }

        private static void SendPacket(byte id, byte[] payload)
        {
            int len;

            if (payload != null)
            {
                len = payload.Length;
            }
            else
            {
                len = 0;
            }

            byte[] buf = new byte[] { HEADER_LENGTH, (byte)len, PROTOVER, (byte)(counter & 0xFF), (byte)(counter >> 8), id };
            counter++;

            List<byte> p = new List<byte>();

            p.AddRange(buf);

            if(payload != null)
                p.AddRange(payload);

            CapturePacket(p.ToArray(), false);

            byte[] encodedpacket = encodeToSLIP(p.ToArray());

            port.Write(encodedpacket, 0, encodedpacket.Length);

//            capturebuf.Add(encodedpacket);
//            dumpPacket(encodedpacket);
        }

        private static void SendTK(byte[] TK)
        {
            byte[] TKmod = new byte[16];

            if(TK != null)
            {
                for(int i = 0; i < TK.Length && i < TKmod.Length; i++)
                {
                    TKmod[i] = TK[i];
                }
            }

            SendPacket(SET_TEMPORARY_KEY, TKmod);

        }

        private static byte[] encodeToSLIP(byte[] packet)
        {
            var al = new List<byte>();

            al.Add(SLIP_START);

            foreach(byte i in packet)
            {
                switch (i)
                {
                    case SLIP_START:
                        al.Add(SLIP_ESC);
                        al.Add(SLIP_ESC_START);
                        break;
                    case SLIP_END:
                        al.Add(SLIP_ESC);
                        al.Add(SLIP_ESC_END);
                        break;
                    case SLIP_ESC:
                        al.Add(SLIP_ESC);
                        al.Add(SLIP_ESC_ESC);
                        break;
                    default:
                        al.Add(i);
                        break;
                }
            }

            al.Add(SLIP_END);

            return al.ToArray();
        }

        private static void dumpPacket(byte[] packet)
        {
            for (int i = 0; i < packet.Length; i += 16)
            {
                int off = 0;
                for (int j = i; j < i + 16 && j < packet.Length; j++)
                {
                    off++;
                    Console.Write("{0:X2} ", (int)packet[j]);
                }

                for (int k = 0; k < 16 - off; k++)
                {
                    Console.Write("   ");
                }

                Console.Write("  ");

                for (int j = i; j < i + 16 && j < packet.Length; j++)
                {
                    Console.Write("{0}", packet[j] > 32 && packet[j] < 256 ? (char)packet[j] : '.');
                }
                Console.Write("\n");
            }

            Console.WriteLine();
        }
    }
}
