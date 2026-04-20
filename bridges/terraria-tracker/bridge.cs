// bridge.cs — C# Reflection Bridge for Frida CLR REPL
//
// Compiled at runtime by repl.py using:
//   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:bridge.dll bridge.cs
//
// IMPORTANT: Must compile with .NET 4.0 csc.exe — no C# 6+ features allowed.
// No ?. operator, no pattern matching (is Type var), no string interpolation.
//
// Loaded into the game process via ICLRRuntimeHost::ExecuteInDefaultAppDomain.
// Entry point signature required: static int Execute(string command)
// Results written to %TEMP%\frida_clr_bridge\bridge_result.json

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace FridaBridge
{
    public class Bridge
    {
        static readonly string ResultPath = Path.Combine(
            Path.GetTempPath(), "frida_clr_bridge", "bridge_result.json");

        // UTF-8 without BOM — Frida's File.readAllText chokes on BOM
        static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        // Required signature for ExecuteInDefaultAppDomain
        public static int Execute(string command)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ResultPath));
                string result = Dispatch(command.Trim());
                File.WriteAllText(ResultPath, result, Utf8NoBom);
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ResultPath));
                    File.WriteAllText(ResultPath,
                        JsonObject(new string[] {
                            JsonKV("ok", "false"),
                            JsonKV("error", JsonStr(ex.ToString()))
                        }),
                        Encoding.UTF8);
                }
                catch { }
                return 1;
            }
        }

        static string Dispatch(string command)
        {
            if (command == "assemblies")
                return CmdAssemblies();

            if (command.StartsWith("types "))
                return CmdTypes(command.Substring(6).Trim());

            if (command.StartsWith("fields "))
                return CmdFields(command.Substring(7).Trim());

            if (command.StartsWith("methods "))
                return CmdMethods(command.Substring(8).Trim());

            if (command.StartsWith("read "))
                return CmdRead(command.Substring(5).Trim());

            if (command.StartsWith("readaddr "))
                return CmdReadAddr(command.Substring(9).Trim());

            return JsonObject(new string[] {
                JsonKV("ok", "false"),
                JsonKV("error", JsonStr("Unknown command: " + command))
            });
        }

        // -------------------------------------------------------------------
        // Null-safe helpers (C# 5 compatible)
        // -------------------------------------------------------------------
        static string SafeFullName(Type t)
        {
            if (t == null) return "";
            return t.FullName != null ? t.FullName : t.Name;
        }

        static string SafeDeclaring(MemberInfo m)
        {
            if (m == null || m.DeclaringType == null) return "";
            return m.DeclaringType.FullName != null ? m.DeclaringType.FullName : "";
        }

        // -------------------------------------------------------------------
        // Command: assemblies
        // -------------------------------------------------------------------
        static string CmdAssemblies()
        {
            Assembly[] asms = AppDomain.CurrentDomain.GetAssemblies();
            List<string> items = new List<string>();
            foreach (Assembly asm in asms)
            {
                try
                {
                    items.Add(JsonObject(new string[] {
                        JsonKV("name", JsonStr(asm.GetName().Name)),
                        JsonKV("fullName", JsonStr(asm.FullName)),
                        JsonKV("location", JsonStr(SafeLocation(asm)))
                    }));
                }
                catch { }
            }
            return JsonObject(new string[] {
                JsonKV("ok", "true"),
                JsonKV("command", JsonStr("assemblies")),
                "\"items\":[" + string.Join(",", items) + "]",
                JsonKV("count", items.Count.ToString())
            });
        }

        static string SafeLocation(Assembly asm)
        {
            try { return asm.Location != null ? asm.Location : ""; }
            catch { return "<dynamic>"; }
        }

        // -------------------------------------------------------------------
        // Command: types <assembly>
        // -------------------------------------------------------------------
        static string CmdTypes(string asmName)
        {
            Assembly asm = FindAssembly(asmName);
            if (asm == null)
                return ErrorResult("Assembly not found: " + asmName);

            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }

            List<string> items = new List<string>();
            foreach (Type t in types)
            {
                if (t == null) continue;
                try
                {
                    string fullName = t.FullName != null ? t.FullName : t.Name;
                    string baseType = t.BaseType != null ? (t.BaseType.FullName != null ? t.BaseType.FullName : "") : "";
                    items.Add(JsonObject(new string[] {
                        JsonKV("name", JsonStr(t.Name)),
                        JsonKV("fullName", JsonStr(fullName)),
                        JsonKV("baseType", JsonStr(baseType)),
                        JsonKV("isClass", t.IsClass ? "true" : "false"),
                        JsonKV("isValueType", t.IsValueType ? "true" : "false"),
                        JsonKV("isEnum", t.IsEnum ? "true" : "false")
                    }));
                }
                catch { }
            }
            return JsonObject(new string[] {
                JsonKV("ok", "true"),
                JsonKV("command", JsonStr("types")),
                JsonKV("assembly", JsonStr(asmName)),
                "\"items\":[" + string.Join(",", items) + "]",
                JsonKV("count", items.Count.ToString())
            });
        }

        // -------------------------------------------------------------------
        // Command: fields <Type>
        // -------------------------------------------------------------------
        static string CmdFields(string typeName)
        {
            Type type = FindType(typeName);
            if (type == null)
                return ErrorResult("Type not found: " + typeName);

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy;

            FieldInfo[] fields = type.GetFields(flags);
            List<string> items = new List<string>();
            foreach (FieldInfo f in fields)
            {
                try
                {
                    int offset = -1;
                    // Marshal.OffsetOf only works on value types with sequential layout.
                    // Calling it on managed classes can cause fatal access violations.
                    if (!f.IsStatic && type.IsValueType)
                    {
                        try { offset = (int)Marshal.OffsetOf(type, f.Name); }
                        catch { }
                    }
                    items.Add(JsonObject(new string[] {
                        JsonKV("name", JsonStr(f.Name)),
                        JsonKV("type", JsonStr(SafeFullName(f.FieldType))),
                        JsonKV("isStatic", f.IsStatic ? "true" : "false"),
                        JsonKV("isPublic", f.IsPublic ? "true" : "false"),
                        JsonKV("offset", offset >= 0 ? offset.ToString() : "\"-1\""),
                        JsonKV("declaringType", JsonStr(SafeDeclaring(f)))
                    }));
                }
                catch { }
            }
            return JsonObject(new string[] {
                JsonKV("ok", "true"),
                JsonKV("command", JsonStr("fields")),
                JsonKV("type", JsonStr(typeName)),
                "\"items\":[" + string.Join(",", items) + "]",
                JsonKV("count", items.Count.ToString())
            });
        }

        // -------------------------------------------------------------------
        // Command: methods <Type>
        // -------------------------------------------------------------------
        static string CmdMethods(string typeName)
        {
            Type type = FindType(typeName);
            if (type == null)
                return ErrorResult("Type not found: " + typeName);

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy;

            MethodInfo[] methods = type.GetMethods(flags);
            List<string> items = new List<string>();
            foreach (MethodInfo m in methods)
            {
                try
                {
                    ParameterInfo[] parms = m.GetParameters();
                    List<string> plist = new List<string>();
                    foreach (ParameterInfo p in parms)
                        plist.Add(p.ParameterType.Name + " " + p.Name);

                    items.Add(JsonObject(new string[] {
                        JsonKV("name", JsonStr(m.Name)),
                        JsonKV("returnType", JsonStr(SafeFullName(m.ReturnType))),
                        JsonKV("isStatic", m.IsStatic ? "true" : "false"),
                        JsonKV("isPublic", m.IsPublic ? "true" : "false"),
                        JsonKV("parameters", JsonStr(string.Join(", ", plist))),
                        JsonKV("declaringType", JsonStr(SafeDeclaring(m)))
                    }));
                }
                catch { }
            }
            return JsonObject(new string[] {
                JsonKV("ok", "true"),
                JsonKV("command", JsonStr("methods")),
                JsonKV("type", JsonStr(typeName)),
                "\"items\":[" + string.Join(",", items) + "]",
                JsonKV("count", items.Count.ToString())
            });
        }

        // -------------------------------------------------------------------
        // Command: read <path>
        // -------------------------------------------------------------------
        static string CmdRead(string path)
        {
            object value;
            Type valueType;
            try
            {
                ResolvePath(path, out value, out valueType);
            }
            catch (Exception ex)
            {
                return ErrorResult("Failed to resolve path '" + path + "': " + ex.Message);
            }

            string display;
            string typeStr = valueType != null ? SafeFullName(valueType) : "null";
            if (value == null)
            {
                display = "null";
            }
            else if (valueType.IsPrimitive || valueType == typeof(string) || valueType == typeof(decimal))
            {
                display = value.ToString();
            }
            else if (valueType.IsValueType)
            {
                // For structs like Vector2, dump all fields
                display = DumpStruct(value, valueType);
            }
            else
            {
                display = value.ToString();
            }

            return JsonObject(new string[] {
                JsonKV("ok", "true"),
                JsonKV("command", JsonStr("read")),
                JsonKV("path", JsonStr(path)),
                JsonKV("type", JsonStr(typeStr)),
                JsonKV("value", JsonStr(display))
            });
        }

        // -------------------------------------------------------------------
        // Command: readaddr <path>
        // -------------------------------------------------------------------
        static string CmdReadAddr(string path)
        {
            string[] parts = ParsePathParts(path);
            if (parts.Length < 2)
                return ErrorResult("readaddr requires at least Type.field");

            string lastPart = parts[parts.Length - 1];

            // Resolve everything except the last part
            string parentPath = string.Join(".", parts, 0, parts.Length - 1);
            string fieldName = lastPart;
            int arrIdx = -1;
            if (fieldName.Contains("["))
            {
                int bi = fieldName.IndexOf('[');
                arrIdx = int.Parse(fieldName.Substring(bi + 1, fieldName.IndexOf(']') - bi - 1));
                fieldName = fieldName.Substring(0, bi);
            }

            object parent;
            Type parentType;
            try
            {
                ResolvePath(parentPath, out parent, out parentType);
            }
            catch (Exception ex)
            {
                return ErrorResult("Failed to resolve parent path: " + ex.Message);
            }

            if (parent == null)
                return ErrorResult("Parent object is null");

            try
            {
                const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                    | BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy;

                if (!string.IsNullOrEmpty(fieldName))
                {
                    FieldInfo fi = parentType.GetField(fieldName, flags);
                    if (fi == null)
                    {
                        PropertyInfo pi = parentType.GetProperty(fieldName, flags);
                        if (pi != null)
                        {
                            object val = pi.GetValue(parent, null);
                            if (arrIdx >= 0 && val is Array)
                                val = ((Array)val).GetValue(arrIdx);
                            return PinAndReturn(val, path);
                        }
                        return ErrorResult("Field not found: " + fieldName + " on " + parentType.FullName);
                    }

                    if (fi.IsStatic)
                    {
                        object val = fi.GetValue(null);
                        if (arrIdx >= 0 && val is Array)
                            val = ((Array)val).GetValue(arrIdx);
                        return PinAndReturn(val, path);
                    }

                    // Instance field: pin the parent object, compute address
                    if (!parentType.IsValueType)
                    {
                        GCHandle handle = GCHandle.Alloc(parent, GCHandleType.Pinned);
                        try
                        {
                            IntPtr objAddr = handle.AddrOfPinnedObject();
                            int offset = (int)Marshal.OffsetOf(parentType, fi.Name);
                            IntPtr fieldAddr = IntPtr.Add(objAddr, offset);

                            if (arrIdx >= 0)
                            {
                                object arrVal = fi.GetValue(parent);
                                if (arrVal is Array)
                                {
                                    Array arr2 = (Array)arrVal;
                                    GCHandle arrHandle = GCHandle.Alloc(arr2, GCHandleType.Pinned);
                                    try
                                    {
                                        IntPtr arrBase = arrHandle.AddrOfPinnedObject();
                                        int elemSize = Marshal.SizeOf(arr2.GetType().GetElementType());
                                        IntPtr elemAddr = IntPtr.Add(arrBase, arrIdx * elemSize);
                                        return JsonObject(new string[] {
                                            JsonKV("ok", "true"),
                                            JsonKV("command", JsonStr("readaddr")),
                                            JsonKV("path", JsonStr(path)),
                                            JsonKV("address", JsonStr("0x" + elemAddr.ToString("X"))),
                                            JsonKV("note", JsonStr("GC may move this object"))
                                        });
                                    }
                                    finally { arrHandle.Free(); }
                                }
                            }

                            return JsonObject(new string[] {
                                JsonKV("ok", "true"),
                                JsonKV("command", JsonStr("readaddr")),
                                JsonKV("path", JsonStr(path)),
                                JsonKV("address", JsonStr("0x" + fieldAddr.ToString("X"))),
                                JsonKV("offset", offset.ToString()),
                                JsonKV("note", JsonStr("GC may move this object"))
                            });
                        }
                        finally { handle.Free(); }
                    }
                }

                // Fallback: just pin the resolved value itself
                object resolved;
                Type resolvedType;
                ResolvePath(path, out resolved, out resolvedType);
                return PinAndReturn(resolved, path);
            }
            catch (Exception ex)
            {
                return ErrorResult("readaddr failed: " + ex.Message);
            }
        }

        static string PinAndReturn(object val, string path)
        {
            if (val == null)
                return ErrorResult("Value is null, cannot get address");

            if (val.GetType().IsValueType)
            {
                object boxed = val;
                GCHandle handle = GCHandle.Alloc(boxed, GCHandleType.Pinned);
                try
                {
                    IntPtr addr = handle.AddrOfPinnedObject();
                    return JsonObject(new string[] {
                        JsonKV("ok", "true"),
                        JsonKV("command", JsonStr("readaddr")),
                        JsonKV("path", JsonStr(path)),
                        JsonKV("address", JsonStr("0x" + addr.ToString("X"))),
                        JsonKV("type", JsonStr(val.GetType().FullName)),
                        JsonKV("note", JsonStr("Pinned boxed copy - address valid only momentarily"))
                    });
                }
                finally { handle.Free(); }
            }
            else
            {
                GCHandle handle = GCHandle.Alloc(val, GCHandleType.Pinned);
                try
                {
                    IntPtr addr = handle.AddrOfPinnedObject();
                    return JsonObject(new string[] {
                        JsonKV("ok", "true"),
                        JsonKV("command", JsonStr("readaddr")),
                        JsonKV("path", JsonStr(path)),
                        JsonKV("address", JsonStr("0x" + addr.ToString("X"))),
                        JsonKV("type", JsonStr(val.GetType().FullName)),
                        JsonKV("note", JsonStr("GC may move this object"))
                    });
                }
                finally { handle.Free(); }
            }
        }

        // -------------------------------------------------------------------
        // Path resolution: Terraria.Main.player[0].position.X
        // -------------------------------------------------------------------
        static void ResolvePath(string path, out object value, out Type valueType)
        {
            string[] parts = ParsePathParts(path);
            if (parts.Length == 0)
                throw new ArgumentException("Empty path");

            // Try progressively longer type-name prefixes
            Type type = null;
            int fieldStart = 0;

            for (int i = 1; i <= parts.Length; i++)
            {
                string candidateName = string.Join(".", parts, 0, i);
                candidateName = StripArrayIndices(candidateName);
                type = FindType(candidateName);
                if (type != null)
                {
                    fieldStart = i;
                    break;
                }
            }

            if (type == null)
                throw new Exception("Could not resolve type from path: " + path);

            if (fieldStart >= parts.Length)
            {
                value = null;
                valueType = type;
                return;
            }

            // Walk the remaining parts as field/property accesses
            object current = null; // null means static context
            Type currentType = type;

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy;

            for (int i = fieldStart; i < parts.Length; i++)
            {
                string part = parts[i];
                string memberName = part;
                int arrayIndex = -1;

                if (memberName.Contains("["))
                {
                    int bracketStart = memberName.IndexOf('[');
                    string indexStr = memberName.Substring(bracketStart + 1,
                        memberName.IndexOf(']') - bracketStart - 1);
                    arrayIndex = int.Parse(indexStr);
                    memberName = memberName.Substring(0, bracketStart);
                }

                // Try field first
                FieldInfo fi = currentType.GetField(memberName, flags);
                if (fi != null)
                {
                    current = fi.GetValue(fi.IsStatic ? null : current);
                    currentType = fi.FieldType;
                }
                else
                {
                    // Try property
                    PropertyInfo pi = currentType.GetProperty(memberName, flags);
                    if (pi != null)
                    {
                        current = pi.GetValue(current, null);
                        currentType = pi.PropertyType;
                    }
                    else
                    {
                        throw new Exception("Member '" + memberName + "' not found on type " +
                            currentType.FullName);
                    }
                }

                // Handle array indexing
                if (arrayIndex >= 0 && current != null)
                {
                    if (current is Array)
                    {
                        Array arr = (Array)current;
                        current = arr.GetValue(arrayIndex);
                        if (current != null)
                            currentType = current.GetType();
                        else
                        {
                            Type elemType = currentType.GetElementType();
                            currentType = elemType != null ? elemType : typeof(object);
                        }
                    }
                    else if (current is IList)
                    {
                        IList list = (IList)current;
                        current = list[arrayIndex];
                        currentType = current != null ? current.GetType() : typeof(object);
                    }
                    else
                    {
                        throw new Exception("Cannot index non-array/list: " + currentType.FullName);
                    }
                }
            }

            value = current;
            valueType = current != null ? current.GetType() : currentType;
        }

        static string[] ParsePathParts(string path)
        {
            return path.Split('.');
        }

        static string StripArrayIndices(string s)
        {
            StringBuilder sb = new StringBuilder();
            bool inBracket = false;
            foreach (char c in s)
            {
                if (c == '[') { inBracket = true; continue; }
                if (c == ']') { inBracket = false; continue; }
                if (!inBracket) sb.Append(c);
            }
            return sb.ToString();
        }

        // -------------------------------------------------------------------
        // Type & Assembly resolution
        // -------------------------------------------------------------------
        static Assembly FindAssembly(string name)
        {
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    if (asm.GetName().Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                        return asm;
                }
                catch { }
            }
            // Partial match
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    if (asm.GetName().Name.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                        return asm;
                }
                catch { }
            }
            return null;
        }

        static Type FindType(string fullName)
        {
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    Type t = asm.GetType(fullName, false);
                    if (t != null) return t;
                }
                catch { }
            }
            // Case-insensitive fallback
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    Type t = asm.GetType(fullName, false, true);
                    if (t != null) return t;
                }
                catch { }
            }
            return null;
        }

        // -------------------------------------------------------------------
        // Struct dumping
        // -------------------------------------------------------------------
        static string DumpStruct(object value, Type type)
        {
            FieldInfo[] fields = type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            List<string> parts = new List<string>();
            parts.Add(type.Name + " {");
            foreach (FieldInfo f in fields)
            {
                try
                {
                    object fv = f.GetValue(value);
                    parts.Add("  " + f.Name + " = " + (fv != null ? fv.ToString() : "null"));
                }
                catch { }
            }
            parts.Add("}");
            return string.Join("\n", parts);
        }

        // -------------------------------------------------------------------
        // Minimal JSON helpers (no external dependencies)
        // -------------------------------------------------------------------
        static string ErrorResult(string msg)
        {
            return JsonObject(new string[] {
                JsonKV("ok", "false"),
                JsonKV("error", JsonStr(msg))
            });
        }

        static string JsonObject(string[] kvPairs)
        {
            return "{" + string.Join(",", kvPairs) + "}";
        }

        static string JsonKV(string key, string jsonValue)
        {
            return "\"" + key + "\":" + jsonValue;
        }

        static string JsonStr(string value)
        {
            if (value == null) return "null";
            StringBuilder sb = new StringBuilder("\"");
            foreach (char c in value)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.AppendFormat("\\u{0:X4}", (int)c);
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append("\"");
            return sb.ToString();
        }
    }
}
