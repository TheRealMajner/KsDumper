using System;

namespace KsDumperClient.Utility
{
    public static class EntropyCalculator
    {
        public static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            int[] freq = new int[256];
            foreach (byte b in data) freq[b]++;
            double entropy = 0;
            int len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        public static string EntropyLabel(double entropy)
        {
            if (entropy < 1.0) return "Empty/Unused";
            if (entropy < 3.0) return "Low (code/data)";
            if (entropy < 5.0) return "Normal";
            if (entropy < 6.5) return "High (compressed)";
            if (entropy < 7.5) return "Very High (encrypted)";
            return "Maximum (packed/random)";
        }

        public static System.Drawing.Color EntropyColor(double entropy)
        {
            if (entropy < 3.0) return System.Drawing.Color.FromArgb(63, 185, 80);    // Green
            if (entropy < 5.0) return System.Drawing.Color.FromArgb(88, 166, 255);   // Blue
            if (entropy < 6.5) return System.Drawing.Color.FromArgb(210, 153, 34);   // Yellow
            return System.Drawing.Color.FromArgb(248, 81, 73);                        // Red
        }
    }
}
