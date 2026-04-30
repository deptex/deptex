using System.IO;

namespace Example;

public class FileService
{
    public byte[] Read(string name)
    {
        return File.ReadAllBytes(name);
    }
}
