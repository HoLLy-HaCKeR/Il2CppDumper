using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Il2CppDumper.ExecutableFormats;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    class ScriptGenerator
    {
        private readonly Metadata metadata;
        private readonly Il2Cpp il2cpp;
        private readonly Config config;
        private static Dictionary<Il2CppTypeDefinition, int> typeDefImageIndices = new Dictionary<Il2CppTypeDefinition, int>();
        private static Dictionary<Il2CppMethodDefinition, string> methodModifiers = new Dictionary<Il2CppMethodDefinition, string>();

        public ScriptGenerator(Metadata metadata, Il2Cpp il2cpp, Config config)
        {
            this.metadata = metadata;
            this.il2cpp = il2cpp;
            this.config = config;
        }

        public static void DumpScript(Metadata metadata, Il2Cpp il2cpp, Config config) => new ScriptGenerator(metadata, il2cpp, config).DumpScript();

        public void DumpScript()
        {
            //Script
            var writer = new StreamWriter(new FileStream("dump.cs", FileMode.Create), new UTF8Encoding(false));
            var scriptwriter = new StreamWriter(new FileStream("script.py", FileMode.Create), new UTF8Encoding(false));
            scriptwriter.WriteLine(new StreamReader(typeof(Program).Assembly.GetManifestResourceStream("Il2CppDumper.Resources.ida.py")).ReadToEnd());

            //dump image
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++) {
                var imageDef = metadata.imageDefs[imageIndex];
                writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)} - {imageDef.typeStart}\n");
            }

            //dump type
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++) {
                try {
                    var imageDef = metadata.imageDefs[imageIndex];
                    var typeEnd = imageDef.typeStart + imageDef.typeCount;
                    for (int idx = imageDef.typeStart; idx < typeEnd; idx++) {
                        var typeDef = metadata.typeDefs[idx];
                        typeDefImageIndices.Add(typeDef, imageIndex);
                        var isStruct = false;
                        var isEnum = false;
                        var extends = new List<string>();
                        if (typeDef.parentIndex >= 0) {
                            var parent = il2cpp.types[typeDef.parentIndex];
                            var parentName = GetTypeName(parent);
                            if (parentName == "ValueType")
                                isStruct = true;
                            else if (parentName == "Enum")
                                isEnum = true;
                            else if (parentName != "object")
                                extends.Add(parentName);
                        }

                        //implementedInterfaces
                        if (typeDef.interfaces_count > 0) {
                            for (int i = 0; i < typeDef.interfaces_count; i++) {
                                var @interface = il2cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                                extends.Add(GetTypeName(@interface));
                            }
                        }

                        writer.Write($"\n// Namespace: {metadata.GetStringFromIndex(typeDef.namespaceIndex)}\n");
                        writer.Write(GetCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token));
                        if (config.DumpAttribute && (typeDef.flags & TYPE_ATTRIBUTE_SERIALIZABLE) != 0)
                            writer.Write("[Serializable]\n");
                        var visibility = typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
                        switch (visibility) {
                            case TYPE_ATTRIBUTE_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_PUBLIC:
                                writer.Write("public ");
                                break;
                            case TYPE_ATTRIBUTE_NOT_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
                            case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
                                writer.Write("internal ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_PRIVATE:
                                writer.Write("private ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAMILY:
                                writer.Write("protected ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
                                writer.Write("protected internal ");
                                break;
                        }

                        if ((typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0 && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("static ");
                        else if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) == 0 && (typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0)
                            writer.Write("abstract ");
                        else if (!isStruct && !isEnum && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("sealed ");
                        if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0)
                            writer.Write("interface ");
                        else if (isStruct)
                            writer.Write("struct ");
                        else if (isEnum)
                            writer.Write("enum ");
                        else
                            writer.Write("class ");
                        var typeName = GetTypeName(typeDef);
                        writer.Write($"{typeName}");
                        if (extends.Count > 0)
                            writer.Write($" : {string.Join(", ", extends)}");
                        if (config.DumpTypeDefIndex)
                            writer.Write($" // TypeDefIndex: {idx}\n{{");
                        else
                            writer.Write("\n{");
                        //dump field
                        if (config.DumpField && typeDef.field_count > 0) {
                            writer.Write("\n\t// Fields\n");
                            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                            for (var i = typeDef.fieldStart; i < fieldEnd; ++i) {
                                //dump_field(i, idx, i - typeDef.fieldStart);
                                var fieldDef = metadata.fieldDefs[i];
                                var fieldType = il2cpp.types[fieldDef.typeIndex];
                                var fieldDefaultValue = metadata.GetFieldDefaultValueFromIndex(i);
                                writer.Write(GetCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, "\t"));
                                writer.Write("\t");
                                var access = fieldType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
                                switch (access) {
                                    case FIELD_ATTRIBUTE_PRIVATE:
                                        writer.Write("private ");
                                        break;
                                    case FIELD_ATTRIBUTE_PUBLIC:
                                        writer.Write("public ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAMILY:
                                        writer.Write("protected ");
                                        break;
                                    case FIELD_ATTRIBUTE_ASSEMBLY:
                                    case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                                        writer.Write("internal ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                                        writer.Write("protected internal ");
                                        break;
                                }

                                if ((fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) != 0) {
                                    writer.Write("const ");
                                } else {
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                        writer.Write("static ");
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                        writer.Write("readonly ");
                                }

                                writer.Write($"{GetTypeName(fieldType)} {metadata.GetStringFromIndex(fieldDef.nameIndex)}");
                                if (fieldDefaultValue != null && fieldDefaultValue.dataIndex != -1) {
                                    var pointer = metadata.GetDefaultValueFromIndex(fieldDefaultValue.dataIndex);
                                    if (pointer > 0) {
                                        var fieldDefaultValueType = il2cpp.types[fieldDefaultValue.typeIndex];
                                        metadata.Position = pointer;
                                        object val = null;
                                        switch (fieldDefaultValueType.type) {
                                            case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                                                val = metadata.ReadBoolean();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                                                val = metadata.ReadByte();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                                                val = metadata.ReadSByte();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                                                val = BitConverter.ToChar(metadata.ReadBytes(2), 0);
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                                                val = metadata.ReadUInt16();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                                                val = metadata.ReadInt16();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                                                val = metadata.ReadUInt32();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                                                val = metadata.ReadInt32();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                                                val = metadata.ReadUInt64();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                                                val = metadata.ReadInt64();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                                                val = metadata.ReadSingle();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                                                val = metadata.ReadDouble();
                                                break;
                                            case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                                                var len = metadata.ReadInt32();
                                                val = Encoding.UTF8.GetString(metadata.ReadBytes(len));
                                                break;
                                            //case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                                            default:
                                                writer.Write($" /*Default value offset 0x{pointer:X}*/");
                                                break;
                                        }

                                        if (val is string str)
                                            writer.Write($" = \"{ToEscapedString(str)}\"");
                                        else if (val is char c) {
                                            var v = (int)c;
                                            writer.Write($" = '\\x{v:x}'");
                                        } else if (val != null)
                                            writer.Write($" = {val}");
                                    }
                                }

                                if (config.DumpFieldOffset)
                                    writer.Write("; // 0x{0:X}\n", il2cpp.GetFieldOffsetFromIndex(idx, i - typeDef.fieldStart, i));
                                else
                                    writer.Write(";\n");
                            }
                        }

                        //dump property
                        if (config.DumpProperty && typeDef.property_count > 0) {
                            writer.Write("\n\t// Properties\n");
                            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                            for (var i = typeDef.propertyStart; i < propertyEnd; ++i) {
                                var propertyDef = metadata.propertyDefs[i];
                                writer.Write(GetCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, "\t"));
                                writer.Write("\t");
                                if (propertyDef.get >= 0) {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.get];
                                    writer.Write(GetModifiers(methodDef));
                                    var propertyType = il2cpp.types[methodDef.returnType];
                                    writer.Write($"{GetTypeName(propertyType)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                } else if (propertyDef.set > 0) {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.set];
                                    writer.Write(GetModifiers(methodDef));
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart];
                                    var propertyType = il2cpp.types[parameterDef.typeIndex];
                                    writer.Write($"{GetTypeName(propertyType)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }

                                if (propertyDef.get >= 0)
                                    writer.Write("get; ");
                                if (propertyDef.set >= 0)
                                    writer.Write("set; ");
                                writer.Write("}");
                                writer.Write("\n");
                            }
                        }

                        //dump method
                        if (config.DumpMethod && typeDef.method_count > 0) {
                            writer.Write("\n\t// Methods\n");
                            var methodEnd = typeDef.methodStart + typeDef.method_count;
                            for (var i = typeDef.methodStart; i < methodEnd; ++i) {
                                var methodDef = metadata.methodDefs[i];
                                writer.Write(GetCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, "\t"));
                                writer.Write("\t");
                                writer.Write(GetModifiers(methodDef));
                                var methodReturnType = il2cpp.types[methodDef.returnType];
                                var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                                writer.Write($"{GetTypeName(methodReturnType)} {methodName}(");
                                var parameterStrs = new List<string>();
                                for (var j = 0; j < methodDef.parameterCount; ++j) {
                                    var parameterStr = "";
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                    var parameterType = il2cpp.types[parameterDef.typeIndex];
                                    var parameterTypeName = GetTypeName(parameterType);
                                    if ((parameterType.attrs & PARAM_ATTRIBUTE_OPTIONAL) != 0)
                                        parameterStr += "optional ";
                                    if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                        parameterStr += "out ";
                                    parameterStr += $"{parameterTypeName} {parameterName}";
                                    parameterStrs.Add(parameterStr);
                                }

                                writer.Write(string.Join(", ", parameterStrs));
                                if (config.DumpMethodOffset) {
                                    var methodPointer = il2cpp.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                                    if (methodPointer > 0) {
                                        writer.Write("); // RVA: 0x{0:X} Offset: 0x{1:X}\n", methodPointer, il2cpp.MapVATR(methodPointer));
                                        //Script - method
                                        var name = ToEscapedString(HandleSpecialCharacters(typeName + "$$" + methodName));
                                        scriptwriter.WriteLine($"SetName(0x{methodPointer:X}, '{name}')");
                                    } else {
                                        writer.Write("); // -1\n");
                                    }
                                } else {
                                    writer.Write("); \n");
                                }
                            }
                        }

                        writer.Write("}\n");
                    }
                } catch (Exception e) {
                    Console.WriteLine("ERROR: Some errors in dumping");
                    writer.Write("/*");
                    writer.Write(e);
                    writer.Write("*/\n}\n");
                }
            }

            scriptwriter.WriteLine("print('Make method name done')");
            //Script - MetadataUsage
            if (il2cpp.version > 16) {
                scriptwriter.WriteLine("print('Setting MetadataUsage...')");
                foreach (var i in metadata.metadataUsageDic[1]) //kIl2CppMetadataUsageTypeInfo
                {
                    var type = il2cpp.types[i.Value];
                    var typeName = GetTypeName(type, true);
                    var legalName = "Class$" + HandleSpecialCharacters(typeName);
                    scriptwriter.WriteLine($"SetName(0x{il2cpp.metadataUsages[i.Key]:X}, '{legalName}')");
                    scriptwriter.WriteLine($"idc.MakeComm(0x{il2cpp.metadataUsages[i.Key]:X}, r'{typeName}')");
                }

                foreach (var i in metadata.metadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = il2cpp.types[i.Value];
                    var typeName = GetTypeName(type, true);
                    var legalName = "Class$" + HandleSpecialCharacters(typeName);
                    scriptwriter.WriteLine($"SetName(0x{il2cpp.metadataUsages[i.Key]:X}, '{legalName}')");
                    scriptwriter.WriteLine($"idc.MakeComm(0x{il2cpp.metadataUsages[i.Key]:X}, r'{typeName}')");
                }

                foreach (var i in metadata.metadataUsageDic[3]) //kIl2CppMetadataUsageMethodDef
                {
                    var methodDef = metadata.methodDefs[i.Value];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = GetTypeName(typeDef);
                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
                    var legalName = "Method$" + HandleSpecialCharacters(methodName);
                    scriptwriter.WriteLine($"SetName(0x{il2cpp.metadataUsages[i.Key]:X}, '{legalName}')");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2cpp.GetMethodPointer(methodDef.methodIndex, (int)i.Value, imageIndex, methodDef.token);
                    scriptwriter.WriteLine($"idc.MakeComm(0x{il2cpp.metadataUsages[i.Key]:X}, r'0x{methodPointer:X}')");
                }

                foreach (var i in metadata.metadataUsageDic[4]) //kIl2CppMetadataUsageFieldInfo
                {
                    var fieldRef = metadata.fieldRefs[i.Value];
                    var type = il2cpp.types[fieldRef.typeIndex];
                    var typeDef = metadata.typeDefs[type.data.klassIndex];
                    var fieldDef = metadata.fieldDefs[typeDef.fieldStart + fieldRef.fieldIndex];
                    var fieldName = GetTypeName(type, true) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
                    var legalName = "Field$" + HandleSpecialCharacters(fieldName);
                    scriptwriter.WriteLine($"SetName(0x{il2cpp.metadataUsages[i.Key]:X}, '{legalName}')");
                    scriptwriter.WriteLine($"idc.MakeComm(0x{il2cpp.metadataUsages[i.Key]:X}, r'{fieldName}')");
                }

                foreach (var i in metadata.metadataUsageDic[5]) //kIl2CppMetadataUsageStringLiteral
                {
                    scriptwriter.WriteLine($"SetString(0x{il2cpp.metadataUsages[i.Key]:X}, r'{ToEscapedString(metadata.GetStringLiteralFromIndex(i.Value))}')");
                }

                foreach (var i in metadata.metadataUsageDic[6]) //kIl2CppMetadataUsageMethodRef
                {
                    var methodSpec = il2cpp.methodSpecs[i.Value];
                    var methodDef = metadata.methodDefs[methodSpec.methodDefinitionIndex];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = GetTypeName(typeDef);
                    // Class of the method is generic
                    if (methodSpec.classIndexIndex != -1) {
                        var classInst = il2cpp.genericInsts[methodSpec.classIndexIndex];
                        typeName += GetGenericTypeParams(classInst);
                    }

                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
                    // Method itself is generic
                    if (methodSpec.methodIndexIndex != -1) {
                        var methodInst = il2cpp.genericInsts[methodSpec.methodIndexIndex];
                        methodName += GetGenericTypeParams(methodInst);
                    }

                    var legalName = "Method$" + HandleSpecialCharacters(methodName);
                    scriptwriter.WriteLine($"SetName(0x{il2cpp.metadataUsages[i.Key]:X}, '{legalName}')");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2cpp.GetMethodPointer(methodDef.methodIndex, methodSpec.methodDefinitionIndex, imageIndex, methodDef.token);
                    scriptwriter.WriteLine($"idc.MakeComm(0x{il2cpp.metadataUsages[i.Key]:X}, r'0x{methodPointer:X}')");
                }

                scriptwriter.WriteLine("print('Set MetadataUsage done')");
            }

            //Script - MakeFunction
            if (config.MakeFunction) {
                List<ulong> orderedPointers;
                if (il2cpp.version >= 24.2f) {
                    orderedPointers = new List<ulong>();
                    foreach (var methodPointers in il2cpp.codeGenModuleMethodPointers) {
                        orderedPointers.AddRange(methodPointers);
                    }
                } else {
                    orderedPointers = il2cpp.methodPointers.ToList();
                }

                orderedPointers.AddRange(il2cpp.genericMethodPointers.Where(x => x > 0));
                orderedPointers.AddRange(il2cpp.invokerPointers);
                orderedPointers.AddRange(il2cpp.customAttributeGenerators);
                orderedPointers = orderedPointers.OrderBy(x => x).ToList();
                scriptwriter.WriteLine("print('Making function...')");
                for (int i = 0; i < orderedPointers.Count - 1; i++) {
                    scriptwriter.WriteLine($"MakeFunction(0x{orderedPointers[i]:X}, 0x{orderedPointers[i + 1]:X})");
                }

                scriptwriter.WriteLine("print('Make function done, please wait for IDA to complete the analysis')");
            }

            scriptwriter.WriteLine("print('Script finish !')");
            //writer close
            writer.Close();
            scriptwriter.Close();
        }

        private string GetTypeName(Il2CppType type, bool fullName = false)
        {
            string ret;
            switch (type.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = metadata.typeDefs[type.data.klassIndex];
                        ret = string.Empty;
                        if (fullName)
                        {
                            ret = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                            if (ret != string.Empty)
                            {
                                ret += ".";
                            }
                        }
                        ret += GetTypeName(typeDef);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var generic_class = il2cpp.MapVATR<Il2CppGenericClass>(type.data.generic_class);
                        var typeDef = metadata.typeDefs[generic_class.typeDefinitionIndex];
                        ret = metadata.GetStringFromIndex(typeDef.nameIndex);
                        var genericInst = il2cpp.MapVATR<Il2CppGenericInst>(generic_class.context.class_inst);
                        ret += GetGenericTypeParams(genericInst);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2cpp.MapVATR<Il2CppArrayType>(type.data.array);
                        var oriType = il2cpp.GetIl2CppType(arrayType.etype);
                        ret = $"{GetTypeName(oriType)}[{new string(',', arrayType.rank - 1)}]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var oriType = il2cpp.GetIl2CppType(type.data.type);
                        ret = $"{GetTypeName(oriType)}[]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2cpp.GetIl2CppType(type.data.type);
                        ret = $"{GetTypeName(oriType)}*";
                        break;
                    }
                default:
                    ret = TypeString[(int)type.type];
                    break;
            }

            return ret;
        }

        private string GetTypeName(Il2CppTypeDefinition typeDef)
        {
            var ret = string.Empty;
            if (typeDef.declaringTypeIndex != -1)
            {
                ret += GetTypeName(il2cpp.types[typeDef.declaringTypeIndex]) + ".";
            }
            ret += metadata.GetStringFromIndex(typeDef.nameIndex);
            return ret;
        }

        private string GetGenericTypeParams(Il2CppGenericInst genericInst)
        {
            var typeNames = new List<string>();
            var pointers = il2cpp.GetPointers(genericInst.type_argv, (long)genericInst.type_argc);
            for (uint i = 0; i < genericInst.type_argc; ++i)
            {
                var oriType = il2cpp.GetIl2CppType(pointers[i]);
                typeNames.Add(GetTypeName(oriType));
            }
            return $"<{string.Join(", ", typeNames)}>";
        }

        private string GetCustomAttribute(Il2CppImageDefinition image, int customAttributeIndex, uint token, string padding = "")
        {
            if (!config.DumpAttribute || il2cpp.version < 21)
                return string.Empty;
            var index = metadata.GetCustomAttributeIndex(image, customAttributeIndex, token);
            if (index >= 0)
            {
                var attributeTypeRange = metadata.attributeTypeRanges[index];
                var sb = new StringBuilder();
                for (var i = 0; i < attributeTypeRange.count; i++)
                {
                    var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                    var methodPointer = il2cpp.customAttributeGenerators[index];
                    sb.AppendFormat("{0}[{1}] // RVA: 0x{2:X} Offset: 0x{3:X}\n", padding, GetTypeName(il2cpp.types[typeIndex]), methodPointer, il2cpp.MapVATR(methodPointer));
                }
                return sb.ToString();
            }
            else
            {
                return string.Empty;
            }
        }

        private static string GetModifiers(Il2CppMethodDefinition methodDef)
        {
            if (methodModifiers.TryGetValue(methodDef, out string str))
                return str;
            var access = methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
            switch (access)
            {
                case METHOD_ATTRIBUTE_PRIVATE:
                    str += "private ";
                    break;
                case METHOD_ATTRIBUTE_PUBLIC:
                    str += "public ";
                    break;
                case METHOD_ATTRIBUTE_FAMILY:
                    str += "protected ";
                    break;
                case METHOD_ATTRIBUTE_ASSEM:
                case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
                    str += "internal ";
                    break;
                case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
                    str += "protected internal ";
                    break;
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                str += "static ";
            if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
            {
                str += "abstract ";
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_FINAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "sealed override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
                    str += "virtual ";
                else
                    str += "override ";
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) != 0)
                str += "extern ";
            methodModifiers.Add(methodDef, str);
            return str;
        }

        private static string HandleSpecialCharacters(string str)
        {
            str = Regex.Replace(str, @"`\d", "");
            str = str.Replace("<", "_");
            str = str.Replace(">", "_");
            str = str.Replace(",", "_");
            str = str.Replace("-", "_");
            return str;
        }

        private static string ToEscapedString(string s)
        {
            var re = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '\'':
                        re.Append(@"\'");
                        break;
                    case '"':
                        re.Append(@"\""");
                        break;
                    case '\t':
                        re.Append(@"\t");
                        break;
                    case '\n':
                        re.Append(@"\n");
                        break;
                    case '\r':
                        re.Append(@"\r");
                        break;
                    case '\f':
                        re.Append(@"\f");
                        break;
                    case '\b':
                        re.Append(@"\b");
                        break;
                    case '\\':
                        re.Append(@"\\");
                        break;
                    case '\0':
                        re.Append(@"\0");
                        break;
                    case '\u0085':
                        re.Append(@"\u0085");
                        break;
                    case '\u2028':
                        re.Append(@"\u2028");
                        break;
                    case '\u2029':
                        re.Append(@"\u2029");
                        break;
                    default:
                        re.Append(c);
                        break;
                }
            }
            return re.ToString();
        }
    }
}
