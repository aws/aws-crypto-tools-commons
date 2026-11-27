// Prints the public types of the assemblies named on the command line as JSON:
// each type's settable properties and its public methods and constructors.
// read_shipped.py runs it with the released NuGet package as a
// PackageReference (see ReadDotnet.csproj), so every type resolves.
using System.Reflection;
using System.Text.Json;

static string Name(Type t)
{
    if (Nullable.GetUnderlyingType(t) is Type inner) return Name(inner) + "?";
    if (t.IsArray) return Name(t.GetElementType()!) + "[]";
    var name = t.Name;
    if (!t.IsGenericType) return name;
    var args = string.Join(", ", t.GetGenericArguments().Select(Name));
    return $"{name[..name.IndexOf('`')]}<{args}>";
}

static object Param(ParameterInfo p) => new { name = p.Name, type = Name(p.ParameterType) };

var types = new Dictionary<string, object>();
foreach (var assemblyName in args)
{
    // The customer-facing types are in the namespace named after the assembly. The Dafny runtime types are not.
    foreach (var t in Assembly.Load(assemblyName).GetExportedTypes().Where(t => t.Namespace == assemblyName))
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        types[t.Name] = new
        {
            properties = t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.SetMethod?.IsPublic == true)
                .Select(p => new { name = p.Name, type = Name(p.PropertyType) }),
            constructors = t.GetConstructors().Select(c => new { parameters = c.GetParameters().Select(Param) }),
            methods = t.GetMethods(Declared).Where(m => !m.IsSpecialName)
                .Select(m => new { name = m.Name, returns = Name(m.ReturnType), parameters = m.GetParameters().Select(Param) }),
        };
    }
}
Console.WriteLine(JsonSerializer.Serialize(new { types }));
