namespace Il2CppDumper.ExecutableFormats
{
    public class MachoSection
    {
        public string sectname;
        public uint addr;
        public uint size;
        public uint offset;
        public uint flags;
        public uint end;
    }

    public class MachoSection64Bit
    {
        public string sectname;
        public ulong addr;
        public ulong size;
        public ulong offset;
        public uint flags;
        public ulong end;
    }

    public class Fat
    {
        public uint offset;
        public uint size;
        public uint magic;
    }
}
