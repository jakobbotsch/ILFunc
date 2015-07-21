using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ILFunc
{
	internal class Program
	{
		private static int Main(string[] args)
		{
			string ilasmPath = ParseArg(args, "/ilasm") ?? @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe";
			string ildasmPath = ParseArg(args, "/ildasm") ??
			                    @"C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools\ildasm.exe";

			if (!File.Exists(ilasmPath))
			{
				Console.WriteLine("Cannot find ilasm.exe at '{0}'. Please specify with \"/ilasm=<path>\".", ilasmPath);
				Usage();
				return 1;
			}

			if (!File.Exists(ildasmPath))
			{
				Console.WriteLine("Cannot find ildasm.exe at '{0}'. Please specify with \"/ildasm=<path>\".", ildasmPath);
				Usage();
				return 2;
			}

			string pe = args.FirstOrDefault(a => !a.StartsWith("/") && File.Exists(a));

			if (pe == null)
			{
				Console.WriteLine("Cannot find input file");
				Usage();
				return 3;
			}

			string outFile = ParseArg(args, "/out") ?? pe;

			BuildType buildType = BuildType.Agnostic;
			if (args.Contains("/debug", StringComparer.OrdinalIgnoreCase))
				buildType = BuildType.Debug;
			else if (args.Contains("/release", StringComparer.OrdinalIgnoreCase))
				buildType = BuildType.Release;

			return Roundtrip(ildasmPath, ilasmPath, pe, outFile, buildType);
		}

		private static string ParseArg(string[] args, string prefix)
		{
			string value = args.FirstOrDefault(a => a.StartsWith(prefix + "="));
			if (value == null)
				return null;

			return value.Substring(prefix.Length + 1);
		}

		private static void Usage()
		{
			Console.WriteLine(
				"Usage: ILFunc.exe [/ilasm=<path to ilasm.exe>] [/ildasm=<path to ildasm.exe>] [/debug|/release] [/x64|/x86] <path to .exe or .dll> [/out=<path to .exe or .dll>]");
		}

		private static int Roundtrip(string ildasm, string ilasm, string pe, string outFile, BuildType buildType)
		{
			using (TempDir dir = new TempDir())
			{
				string il = Path.Combine(dir.Path, Path.ChangeExtension(Path.GetFileName(pe), ".il"));

				if (!Run(ildasm, $"/linenum /typelist /utf8 /nobar \"{pe}\" \"/out={il}\""))
					return 4;

				string newIL = RewriteIL(File.ReadAllText(il));
				File.WriteAllText(il, newIL, Encoding.UTF8);

				string res = Path.ChangeExtension(il, ".res");
				StringBuilder args = new StringBuilder();
				args.Append("/highentropyva");

				if (buildType == BuildType.Release || buildType == BuildType.Agnostic)
					args.Append(" /debug=opt");
				else if (buildType == BuildType.Debug)
					args.Append(" /debug");

				if (File.Exists(res))
					args.AppendFormat(" \"/resource={0}\"", res);

				args.AppendFormat(" \"{0}\"", il);

				if (Path.GetExtension(pe).Equals(".dll", StringComparison.OrdinalIgnoreCase))
					args.Append(" /dll");

				args.AppendFormat(" \"/output={0}\"", outFile);

				if (!Run(ilasm, args.ToString()))
					return 5;

				return 0;
			}
		}

		private static bool Run(string file, string args)
		{
			ProcessStartInfo processStartInfo = new ProcessStartInfo(file, args)
			{
				WindowStyle = ProcessWindowStyle.Hidden,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};

			Process process = Process.Start(processStartInfo);
			string outputNormal = process.StandardOutput.ReadToEnd();
			string outputError = process.StandardError.ReadToEnd();
			process.WaitForExit();

			if (process.ExitCode != 0)
			{
				Console.WriteLine("'{0}' failed with exit code {1}. Output:", file, process.ExitCode);
				Console.WriteLine(outputNormal);
				Console.WriteLine("Errors:");
				Console.WriteLine(outputError);
				return false;
			}

			return true;
		}

		private static string RewriteIL(string il)
		{
			Regex findIlAttribs =
				new Regex(
					"\\.custom\\s+instance\\s+void\\s+.*?ILFuncAttribute\\s*::\\s*\\.ctor\\s*\\(\\s*string\\s*\\)\\s*=\\s*");
			MatchCollection matches = findIlAttribs.Matches(il);

			List<StringAction> actions = new List<StringAction>();
			
			foreach (Match match in matches.OfType<Match>())
			{
				int end;
				List<byte> bytes = ParseAttributeMetadata(il, match.Index + match.Length, out end);
				// Remove the attribute
				actions.Add(new RemoveBlock(match.Index, end + 1 - match.Index));

				string replacementIL = GetReplacementIL(bytes);
				
				int insertAt = il.IndexOf(".maxstack", FindEndOfLineOrString(il, end), StringComparison.Ordinal);
				Trace.Assert(insertAt != -1);
				// Insert our IL before .maxstack
				actions.Add(new InsertBlock(insertAt, replacementIL + "\r\n"));

				// Remove old IL
				int removeUntil = il.IndexOf("} // end of method", insertAt, StringComparison.Ordinal);
				Trace.Assert(removeUntil != -1);
				actions.Add(new RemoveBlock(insertAt, removeUntil - insertAt));
			}

			StringBuilder sb = new StringBuilder(il);

			int fixup = 0;
			foreach (StringAction action in actions.OrderBy(a => a.Start))
			{
				action.Perform(sb, ref fixup);
			}

			return sb.ToString();
		}

		private static string GetReplacementIL(List<byte> bytes)
		{
			int index = 2;
			int length = ReadPackedLen(bytes, ref index);

			return Encoding.UTF8.GetString(bytes.Skip(index).Take(length).ToArray());
		}

		private static int ReadPackedLen(List<byte> bytes, ref int index)
		{
			byte first = bytes[index];
			index++;
			if ((first & 0x80) == 0)
				return first;

			byte second = bytes[index];
			index++;
			if ((first & 0x40) == 0)
			{
				return ((first & 0x3F) << 8) | second;
			}

			Trace.Assert((first & 0x20) == 0);

			byte third = bytes[index];
			index++;
			byte fourth = bytes[index];
			index++;

			return ((first & 0x1F) << 24) |
			       (second << 16) |
			       (third << 8) |
			       (fourth);
		}

		private static List<byte> ParseAttributeMetadata(string il, int start, out int end)
		{
			List<byte> bytes = new List<byte>();

			bool foundOpeningParens = false;
			int i;
			for (i = start; i < il.Length;)
			{
				if (StringMatch(il, i, "//"))
				{
					i += 2;
					i = FindEndOfLineOrString(il, i);

					continue;
				}

				if (!foundOpeningParens)
				{
					if (StringMatch(il, i, "("))
					{
						foundOpeningParens = true;
					}

					i++;
					continue;
				}

				if (StringMatch(il, i, ")"))
				{
					break;
				}

				byte b;
				if (ParseHex(il, ref i, out b))
				{
					bytes.Add(b);
					continue;
				}

				i++;
			}

			end = i;
			return bytes;
		}

		private static bool StringMatch(string s, int index, string substring)
		{
			if (index + substring.Length > s.Length)
				return false;

			for (int i = 0; i < substring.Length; i++)
			{
				if (s[index + i] != substring[i])
					return false;
			}

			return true;
		}

		private static bool ParseHex(string s, ref int index, out byte b)
		{
			char c = s[index];
			if (c >= '0' && c <= '9')
				b = (byte)(c - '0');
			else if (c >= 'a' && c <= 'f')
				b = (byte)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				b = (byte)(c - 'A' + 10);
			else
			{
				b = 0;
				return false;
			}

			index++;
			if (index >= s.Length)
				return true;

			c = s[index];
			byte next;
			if (c >= '0' && c <= '9')
				next = (byte)(c - '0');
			else if (c >= 'a' && c <= 'f')
				next = (byte)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				next = (byte)(c - 'A' + 10);
			else
				return true;

			b = (byte)((b << 4) | next);
			index++;
			return true;
		}

		private static int FindEndOfLineOrString(string s, int index)
		{
			while (!StringMatch(s, index, "\r\n") && !StringMatch(s, index, "\n") && index < s.Length)
				index++;

			return index;
		}

		private abstract class StringAction
		{
			protected StringAction(int start)
			{
				Start = start;
			}

			public int Start { get; private set; }

			public abstract void Perform(StringBuilder sb, ref int fixup);
		}

		private class RemoveBlock : StringAction
		{
			public RemoveBlock(int start, int count) : base(start)
			{
				Count = count;
			}

			public int Count { get; private set; }

			public override void Perform(StringBuilder sb, ref int fixup)
			{
				sb.Remove(Start + fixup, Count);

				fixup -= Count;
			}
		}

		private class InsertBlock : StringAction
		{
			public InsertBlock(int start, string block) : base(start)
			{
				Block = block;
			}

			public string Block { get; private set; }

			public override void Perform(StringBuilder sb, ref int fixup)
			{
				sb.Insert(Start + fixup, Block);
				fixup += Block.Length;
			}
		}

		private enum BuildType
		{
			Agnostic,
			Debug,
			Release,
		}
	}
}