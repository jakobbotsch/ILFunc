using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace ILFunc
{
	public class TempDir : IDisposable
	{
		public TempDir()
		{
			Path = CreateRandomTempDirectory();
		}

		public string Path { get; private set; }

		private bool _isDisposed;

		public void Dispose()
		{
			if (_isDisposed)
				return;

			Directory.Delete(Path, true);
			_isDisposed = true;
		}

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CreateDirectory(string lpPathName, IntPtr lpSecurityAttributes);

		private static string CreateRandomTempDirectory()
		{
			while (true)
			{
				string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.IO.Path.GetRandomFileName());

				// We cannot use Directory.CreateDirectory as it doesn't fail if the directory already exists,
				// and we need a random NEW directory.
				if (CreateDirectory(path, IntPtr.Zero))
					return path;

				const int ERROR_ALREADY_EXISTS = 183;
				if (Marshal.GetLastWin32Error() == ERROR_ALREADY_EXISTS)
					continue;

				throw new Win32Exception();
			}
		}
	}
}