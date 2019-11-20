using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics.Eventing;

namespace SlipSniff
{

    static class EventWriter
    {
        internal static EventProviderVersionTwo m_provider = new EventProviderVersionTwo(new Guid("e3c99c07-0ea4-463d-b4f6-c9724428d18c"));
        //
        // Task :  eventGUIDs
        //
        private static Guid SampleTaskId = new Guid("29f31d7a-a93c-40a2-b9fe-f7935c113315");

        private static EventDescriptor BLEMesg;

        static EventWriter()
        {
            //unchecked
            //{
            //    BLEMesg = new EventDescriptor();
            //}
        }

        public static void write(byte[] payload)
        {
            EventDescriptor myBLEMesg = new EventDescriptor();
            m_provider.BLEPacket(ref myBLEMesg, payload);
        }
    }

    internal class EventProviderVersionTwo : EventProvider
    {
        internal EventProviderVersionTwo(Guid id)
               : base(id)
        { }


        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct EventData
        {
            [FieldOffset(0)]
            internal UInt64 DataPointer;
            [FieldOffset(8)]
            internal uint Size;
            [FieldOffset(12)]
            internal int Reserved;
        }



        internal unsafe bool BLEPacket(
            ref EventDescriptor eventDescriptor,
                byte[] payload
            )
        {
            int argumentCount = 1;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(payload.Length + 1) * sizeof(char);

                fixed (byte* a0 = payload)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }
    }
}
