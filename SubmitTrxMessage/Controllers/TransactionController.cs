using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using TransactionApi.Class;
using static TransactionApi.Class.clsRequestTransaction;

namespace TransactionApi.Controllers
{
    [Route("api")]
    [ApiController]

    public class TransactionController : Controller
    {
        // Store the partnerKey & partnerRefNo
        private static readonly Dictionary<string, string> allowedPartners = new Dictionary<string, string>
        {
            { "FAKEGOOGLE", "FAKEPASSWORD1234" },
            { "FAKEPEOPLE", "FAKEPASSWORD4578" }
        };

        [HttpPost("submittrxmessage")]
        public IActionResult SubmitTransaction([FromBody] TransactionRequest request)
        {
            // Validate the request
            if (request == null)
            {
                return BadRequest(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Invalid request."
                });
            }

            // Validate the requested field
            if (validateRequiredField(request).isValid == false)
            {
                string missingField = validateRequiredField(request).missingField;
                return BadRequest(new FailedResponse
                {
                    result = 0,
                    resultmessage = $"{missingField} is required."
                });
            }

            // Validate total amount
            if (validateTotalAmount(request) == false)
            {
                return BadRequest(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Total Amount must be positive value."
                });
            }

            // Verify partner password (Base64)
            if (!allowedPartners.ContainsKey(request.partnerkey) ||
                allowedPartners[request.partnerkey] != DecodeBase64(request.partnerpassword))
            {
                return Unauthorized(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Access Denied!"
                });
            }

            // Validate the timestamp (check for expiry)
            if (!ValidateTimestamp(request))
            {
                return Unauthorized(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Expired."
                });
            }

            // Validate the signature
            if (!ValidateSignature(request))
            {
                return Unauthorized(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Invalid Signature."
                });
            }

            // Calculate the request price and compare with total
            var totalItemAmount = request.items?.Sum(i => i.qty * i.unitprice) ?? 0; // If items is null, assume total = 0
            if (request.totalamount != totalItemAmount)
            {
                return BadRequest(new FailedResponse
                {
                    result = 0,
                    resultmessage = "Invalid Total Amount."
                });
            }

            // Get discount
            var discountAmount = CheckDiscount(request.totalamount ?? 0);

            // Return response
            var totalAmount = request.totalamount ?? 0;
            var finalAmount = totalAmount - discountAmount; 
            return Ok(new SuccessResponse
            {
                result = 1,
                totalamount = totalAmount,
                totaldiscount = discountAmount,
                finalamount = finalAmount
            });
        }

        // Validate requested field
        private (bool isValid, string missingField) validateRequiredField(TransactionRequest request)
        {
            // Check each mandatory field 
            if (string.IsNullOrEmpty(request.partnerkey))
            {
                return (false, "partnerkey");
            }
            if (string.IsNullOrEmpty(request.partnerrefno))
            {
                return (false, "partnerrefno");
            }
            if (string.IsNullOrEmpty(request.partnerpassword))
            {
                return (false, "partnerpassword");
            }
            if (string.IsNullOrEmpty(request.timestamp))
            {
                return (false, "timestamp");
            }
            if (request.totalamount == null)
            {
                return (false, "totalamount");
            }
            if (string.IsNullOrEmpty(request.sig))
            {
                return (false, "sig");
            }

            return (true, null);
        }

        // Validate total amount
        private bool validateTotalAmount(TransactionRequest request)
        {
            // Validate all fields are present
            if (request.totalamount < 0)
            {
                return false;
            }

            return true;
        }

        // Validate the time stamp
        private bool ValidateTimestamp(TransactionRequest request)
        {
            DateTimeOffset timestamp;
            if (!DateTimeOffset.TryParseExact(request.timestamp, "yyyy-MM-ddTHH:mm:ss.fffffffZ",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out timestamp))
            {
                return false;
            }

            // Get current time
            DateTimeOffset serverTime = DateTimeOffset.UtcNow;

            // Define the time range (±5 minutes)
            TimeSpan maxDifference = TimeSpan.FromMinutes(5);

            // Calculate difference of the time
            TimeSpan timeDifference = serverTime - timestamp;

            // If difference greater than 5min then return false (expired)
            if (Math.Abs(timeDifference.TotalMinutes) > 5)
            {
                return false;
            }

            return true;
        }

        // Decode Base64 string
        private string DecodeBase64(string encoded)
        {
            var bytes = Convert.FromBase64String(encoded);
            return Encoding.UTF8.GetString(bytes);
        }

        // Validate the signature (sig)
        private bool ValidateSignature(TransactionRequest request)
        {
            // Parse and reformat the timestamp to "yyyyMMddHHmmss" format
            DateTimeOffset timestamp;
            if (!DateTimeOffset.TryParseExact(request.timestamp, "yyyy-MM-ddTHH:mm:ss.fffffffZ",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out timestamp))
            {
                return false; 
            }

            // Convert DateTimeOffset to the required "yyyyMMddHHmmss" format
            var formattedTimestamp = timestamp.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);

            // For checking the timestamp is in correct format or not
            // Console.WriteLine($"Formatted Timestamp: {formattedTimestamp}");

            // Concatenate the parameters in the required order for the signature
            var data = $"{formattedTimestamp}{request.partnerkey}{request.partnerrefno}{request.totalamount}{request.partnerpassword}";

            // For checking the joined data 
            // Console.WriteLine($"Data: {data}");

            // Compute the SHA-256 hash and encode it into Base64
            var base64Hash = GenerateSignature(data);

            // Compare the Base64 hash with request signature
            return base64Hash == request.sig;
        }

        private string ComputeSha256HashHexLowerCase(string rawData)
        {
            using (var sha256 = SHA256.Create())
            {
                // Compute SHA-256 hash as a byte array
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert the byte array to a lowercase hexadecimal string
                StringBuilder hexString = new StringBuilder(bytes.Length * 2);
                foreach (byte b in bytes)
                {
                    hexString.Append(b.ToString("x2")); // 'x2' for lowercase hexadecimal format
                }

                return hexString.ToString();
            }
        }

        private string GenerateSignature(string rawData)
        {
            // Get the hex 
            string hex = ComputeSha256HashHexLowerCase(rawData);

            // Encode it with UTF8
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(hex);

            // Encode the bytes to base64
            string base64Encoded = Convert.ToBase64String(plainTextBytes);

            // For console checking
            // Console.WriteLine("Base64 Encoded: " + base64Encoded2); 

            return base64Encoded;
        }

        // Check discount
        private long CheckDiscount(long totalAmount)
        {
            long discount = 0;
            int discountPercant = 0;
            int amount = (int)(totalAmount / 100);

            // Base discount 
            if (amount < 200) // less than MYR 200 
            {
                discountPercant = 0;
            }
            else if (amount >= 200 && amount <= 500) // between MYR 200 and MYR 500 (inclusive)
            {
                discountPercant = 5;
            }
            else if (amount >= 501 && amount <= 800) // between MYR 501 and MYR 800 (inclusive)
            {
                discountPercant = 7;
            }
            else if (amount >= 801 && amount <= 1200) // between MYR 801 and MYR 1200 (inclusive):
            {
                discountPercant = 10;
            }           
            else if (amount > 1200) // greater than MYR 1200:
            {              
                discountPercant = 15;
            }
        
            // Conditional discounts
            if (amount > 500 && IsPrime(totalAmount)) // Additional 8% discount if prime
            {
                discountPercant += 8; 
            }

            if (amount > 900 && amount % 10 == 5) // Additional 10% discount if ends with 5
            {
                discountPercant += 10; 
            }

            // Cap on Maximum Discount
            if (discountPercant > 20) 
            {
                discountPercant = 20;
            }

            // Calculate the discount
            discount += (long)(amount * discountPercant);

            return discount;
        }

        // Check is prime number or not
        private bool IsPrime(long number)
        {
            if (number <= 1) return false;
            if (number == 2) return true;
            if (number % 2 == 0) return false;

            for (long i = 3; i * i <= number; i += 2)
            {
                if (number % i == 0) return false;
            }

            return true;
        }

    }
}
