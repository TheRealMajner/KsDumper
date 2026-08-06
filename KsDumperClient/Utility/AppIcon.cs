using System.Drawing;
using System.IO;
using System.Reflection;

namespace KsDumperClient.Utility
{
    public static class AppIcon
    {
        private static Icon _cached;

        public static Icon Get()
        {
            if (_cached != null) return _cached;

            // Try embedded resource first
            var assembly = Assembly.GetExecutingAssembly();
            using (var stream = assembly.GetManifestResourceStream("KsDumperClient.image.ico"))
            {
                if (stream != null)
                {
                    _cached = new Icon(stream);
                    return _cached;
                }
            }

            // Fallback to file
            if (File.Exists("image.ico"))
            {
                _cached = new Icon("image.ico");
                return _cached;
            }

            return null;
        }
    }
}
