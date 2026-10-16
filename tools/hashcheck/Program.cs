using System.Text;
using RdpClient.Protocol.Security;

(string Password, string Expected)[] vectors =
[
    ("password", "8846f7eaee8fb117ad06bdd830b7586c"),
    ("",         "31d6cfe0d16ae931b73c59d7e0c089c0"),
    ("Password", "a4f49c406510bdcab6824ee7c30fd852"),
    ("P@ssw0rd","eb93429a8bd952f8b89c55b87f475edc"),
];

foreach (var (password, expected) in vectors)
{
    var actual = Convert.ToHexString(Ntlm.NtHash(password)).ToLowerInvariant();
    Console.WriteLine($"{actual == expected,5}  NtHash(\"{password}\") = {actual}");
}
