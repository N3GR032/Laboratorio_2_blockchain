using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        try
        {
            RSACryptoServiceProvider rsa = null;
            byte[] mensajeBytes = null;

            while (true)
            {
                Console.WriteLine("Seleccione una opción:");
                Console.WriteLine("1. Generar par de claves");
                Console.WriteLine("2. Firmar");
                Console.WriteLine("3. Verificar firma");
                Console.WriteLine("4. Salir");
                Console.Write("Opción: ");
                string opcion = Console.ReadLine();

                switch (opcion)
                {
                    case "1":
                        rsa = new RSACryptoServiceProvider();
                        RSAParameters privateKey = rsa.ExportParameters(true);
                        RSAParameters publicKey = rsa.ExportParameters(false);

                        // Crear una carpeta para las claves privadas si no existe
                        string privateKeyFolder = "PrivateKeys";
                        Directory.CreateDirectory(privateKeyFolder);

                        // Guardar la clave pública en un archivo
                        string publicKeyPath = "publicKey.txt";
                        File.WriteAllText(publicKeyPath, ToXmlString(publicKey));
                        Console.WriteLine($"Clave pública guardada en {publicKeyPath}");

                        // Guardar la clave privada en la carpeta PrivateKeys
                        File.WriteAllText(Path.Combine(privateKeyFolder, "privateKey.txt"), ToXmlString(privateKey));

                        Console.WriteLine("Par de claves generado, clave pública guardada en publicKey.txt y clave privada en la carpeta PrivateKeys");
                        break;

                    case "2":
                        if (rsa == null)
                        {
                            Console.WriteLine("Primero necesita generar un par de claves (opción 1)");
                            break;
                        }

                        Console.Write("Ingrese el mensaje a firmar: ");
                        string mensaje = Console.ReadLine();
                        mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);

                        // Guardar el mensaje en un archivo
                        string mensajePath = "mensaje.txt";
                        File.WriteAllText(mensajePath, mensaje);
                        Console.WriteLine($"Mensaje guardado en {mensajePath}");

                        byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                        File.WriteAllBytes("firma.txt", firma);
                        Console.WriteLine("Mensaje firmado y firma guardada en firma.txt");
                        break;

                    case "3":
                        if (rsa == null)
                        {
                            Console.WriteLine("Primero necesita generar un par de claves (opción 1)");
                            break;
                        }

                        if (mensajeBytes == null)
                        {
                            Console.WriteLine("Primero necesita firmar un mensaje (opción 2)");
                            break;
                        }

                        Console.Write("Ingrese el nombre del archivo que contiene el mensaje: ");
                        string mensajeArchivo = Console.ReadLine();

                        Console.Write("Ingrese el nombre del archivo que contiene la firma: ");
                        string firmaArchivo = Console.ReadLine();

                        byte[] mensajeVerificar = File.ReadAllBytes(mensajeArchivo);
                        byte[] firmaVerificar = File.ReadAllBytes(firmaArchivo);

                        bool verificado = rsa.VerifyData(mensajeVerificar, firmaVerificar, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        if (verificado)
                        {
                            Console.WriteLine("La firma es válida.");
                        }
                        else
                        {
                            Console.WriteLine("La firma es inválida.");
                        }
                        break;

                    case "4":
                        return;

                    default:
                        Console.WriteLine("Opción no válida, por favor seleccione una opción válida.");
                        break;
                }
            }
        }
        catch (CryptographicException e)
        {
            Console.WriteLine($"Error de criptografía: {e.Message}");
        }
    }

    // Método para convertir los parámetros RSA a XML
    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}
