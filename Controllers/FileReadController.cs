using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;
using WebApiReadFile7.Dbcontext;
using WebApiReadFile7.Models;

namespace WebApiReadFile7.Controllers
{
    public class Test
    {
        public DateTime date { get; set; }
        public int temperatureC { get; set; }
        public int temperatureF { get; set; }
        public string summary { get; set; }
    }
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class FileReadController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        public FileReadController(ApplicationDbContext context)
        {
            _context = context;
        }
        private static byte[] GetKeyBytes(string key)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }
        private static string DecryptString(string cipherText, string key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                var iv = new byte[aesAlg.BlockSize / 8];
                var cipher = new byte[fullCipher.Length - iv.Length];

                Array.Copy(fullCipher, iv, iv.Length);
                Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                using (var decryptor = aesAlg.CreateDecryptor(GetKeyBytes(key), iv))
                using (var msDecrypt = new MemoryStream(cipher))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
        private static string EncryptString(string plainText, string key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(GetKeyBytes(key), aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
        [HttpGet]
        public async Task<IActionResult> saveFile()
        {
            var obj = new Test
            {
                date = DateTime.Now,
                temperatureC = 40,
                temperatureF = 20,
                summary = "asdasfdsadfsdf asdsada"
            };

            var jsonString = JsonConvert.SerializeObject(obj);
            var folderPath = @"F:\FellowProAPi\TextFile";

            var encryptedString = EncryptString(jsonString, "your-encryption-key");

            // Save the encrypted string to a text file
            var filePath = Path.Combine(folderPath, "encryptedFile.txt");
            await System.IO.File.WriteAllTextAsync(filePath, encryptedString);





            var jsonString1 = DecryptString(encryptedString, "your-encryption-key");
            var obj2 = JsonConvert.DeserializeObject<Test>(jsonString1);
            return Ok(obj2);
        }


        [HttpGet]
        public async Task<IActionResult> GetFileData()
        {
            var folderPath = @"F:\FellowProAPi\TextFile";

            try
            {
                var files = Directory.GetFiles(folderPath);

                if (files.Length == 0)
                {
                    return NotFound("No files found in the folder.");
                }

                var firstFile = files[0];
                var fileContent = System.IO.File.ReadAllText(firstFile);

                var jsonString1 = DecryptString(fileContent, "your-encryption-key");
                var obj2 = JsonConvert.DeserializeObject<Test>(jsonString1);
                return Ok(obj2);
            }
            catch (Exception ex)
            {

                throw;
            }
                        
        }

        [HttpGet]
        public async Task<IActionResult> GetFileContent()
        {
            // Define the path to the folder in the F: drive
            var folderPath = @"F:\FellowProAPi\TextFile"; // Adjust this path to your specific folder

            var outputDecryptedPath = @"F:\FellowProAPi\DecryptedTextFile";
            byte[] keyAndIvReturn = null;  
            try
            {
                var files = Directory.GetFiles(folderPath);

                if (files.Length == 0)
                {
                    return NotFound("No files found in the folder.");
                }

                var firstFile = files[0];
                var fileContent = System.IO.File.ReadAllText(firstFile);



                //string jsonContent = JsonConvert.SerializeObject(fileContent);

                byte[] jsonBytes = Encoding.UTF8.GetBytes(fileContent);
                // Convert JSON content to byte array
                //byte[] jsonBytes = Encoding.UTF8.GetBytes(jsonContent);

                // Create AES encryption key and IV
                using (Aes aes = Aes.Create())
                {
                    aes.Key = new byte[32]; // 256-bit key
                    aes.IV = new byte[16]; // 128-bit IV

                    // Generate random key and IV
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(aes.Key);
                        rng.GetBytes(aes.IV);
                    }

                    // Encrypt the JSON byte array
                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (var ms = new MemoryStream())
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(jsonBytes, 0, jsonBytes.Length);
                        cs.FlushFinalBlock();

                        // Combine the key, IV, and encrypted content
                        byte[] encryptedContent = ms.ToArray();
                        byte[] keyAndIv = new byte[aes.Key.Length + aes.IV.Length + encryptedContent.Length];
                        Array.Copy(aes.Key, 0, keyAndIv, 0, aes.Key.Length);
                        Array.Copy(aes.IV, 0, keyAndIv, aes.Key.Length, aes.IV.Length);
                        Array.Copy(encryptedContent, 0, keyAndIv, aes.Key.Length + aes.IV.Length, encryptedContent.Length);

                        // Save the encrypted content to the output file
                        //File.WriteAllBytes(outputFilePath, keyAndIv);
                        keyAndIvReturn = keyAndIv;
                    }
                }

                /////////////////////////////////

                string keyAndIvDecriptedText = null;

                byte[] keyAndIvDecript = keyAndIvReturn;

                // Extract the key, IV, and encrypted content
                byte[] key = new byte[32]; // 256-bit key
                byte[] iv = new byte[16]; // 128-bit IV
                byte[] DecriptContent = new byte[keyAndIvDecript.Length - key.Length - iv.Length];

                Array.Copy(keyAndIvDecript, 0, key, 0, key.Length);
                Array.Copy(keyAndIvDecript, key.Length, iv, 0, iv.Length);
                Array.Copy(keyAndIvDecript, key.Length + iv.Length, DecriptContent, 0, DecriptContent.Length);

                // Decrypt the encrypted byte array
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var ms = new MemoryStream(DecriptContent))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        // Read the decrypted content
                        string decryptedContent = sr.ReadToEnd();

                       
                        keyAndIvDecriptedText = decryptedContent;
                    }
                }


                Datalog datalog = new Datalog();
                datalog.Id = 1;
                datalog.FileName = Path.GetFileName(firstFile);
                datalog.RequestJson = keyAndIvDecriptedText;

                _context.Datalogs.Add(datalog);
                //await _context.SaveChangesAsync();

                Directory.CreateDirectory(outputDecryptedPath);

                var decryptedFilePath = Path.Combine(outputDecryptedPath, "DecryptedFile.json");

                System.IO.File.WriteAllText(decryptedFilePath, keyAndIvDecriptedText);





                return Ok(new { FileName = Path.GetFileName(firstFile), Content = keyAndIvReturn, Decript = keyAndIvDecriptedText, DecryptedFilePath = decryptedFilePath });
            }
            catch (DirectoryNotFoundException)
            {
                return NotFound($"Directory '{folderPath}' not found.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
