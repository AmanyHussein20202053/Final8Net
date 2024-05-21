using Final8Net.Data;
using Final8Net.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net.Mail;
using System.Net;
using System.Security.Cryptography;
using Final8Net.Email;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Final8Net.Interfaces;
using Microsoft.AspNetCore.DataProtection;
using System.Text.RegularExpressions;

namespace Final8Net.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;
        private readonly ApplicationDbContext _db;
        private readonly IEmailSender emailSender;
        private readonly IAuthenticationServices _authenticationService;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        public AccountController(IEmailSender emailSender, ILogger<AccountController> logger, ApplicationDbContext db, IAuthenticationServices authenticationService, IDataProtectionProvider dataProtectionProvider)
        {
            this.emailSender = emailSender;
            _db = db;
            _logger = logger;
            _authenticationService = authenticationService;
            _dataProtectionProvider = dataProtectionProvider;
        }
        public bool IsUserAuthenticated => User.Identity.IsAuthenticated;
        private bool isLoggedIn = false;

        [HttpPost]
        public async Task<IActionResult> smth0(string email, string subject, string message , string verificationCode)
        {
            await emailSender.SendEmailAsync(email, subject, message, verificationCode);
            return RedirectToAction("Index", "Home");
        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var student = await _db.student.FirstOrDefaultAsync(s => s.Email == model.Email);

                    if (student != null && VerifyPassword(model.Password, student.Password))
                    {
                        // Create claims for the authenticated user
                        var claims = new[]
                        {
                        new Claim(ClaimTypes.Name, student.Email),
                        new Claim(ClaimTypes.NameIdentifier, student.Email)
                        // Add more claims as needed
                    };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                        var principal = new ClaimsPrincipal(identity);

                        // Sign in the user
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                        // Set ViewBag variable
                        ViewBag.IsLoggedIn = true;

                        // Authentication successful, redirect to home page
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid email or password");
                        return View(model);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "An error occurred while processing the login request.");
                    ModelState.AddModelError(string.Empty, "An error occurred while processing your request. Please try again later.");
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }
        public IActionResult CreateCookie()
        {

            string key = "My_Cookie";
            string value = GenerateRandomString(10);
            IDataProtector protector = _dataProtectionProvider.CreateProtector(typeof(AccountController).FullName);

            // Encrypt the cookie value
            string encryptedValue = protector.Protect(value);

            // Set cookie options
            CookieOptions options = new CookieOptions
            {
                Expires = DateTime.Now.AddMinutes(5),
                HttpOnly = true // Ensure the cookie is accessible only through HTTP
            };

            // Set the encrypted cookie value
            Response.Cookies.Append(key, encryptedValue, options);


            return View("Index");
        }

        private string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public async Task<IActionResult> LogoutAsync()
        {
            if (User.Identity.IsAuthenticated)
            {
                // Remove the authentication cookie
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Alternatively, you can remove the session cookie
                HttpContext.Session.Clear();

                // Redirect to the home page
                return RedirectToAction("Index", "Home");
            }
            else
            {
                _logger.LogWarning("Logout attempted by unauthenticated user.");
                // If the user is not authenticated, simply redirect to the home page
                return RedirectToAction("Index", "Home");
            }
        }

        public IActionResult RemoveCookie()
        {
            string key = "My_Cookie";
            string value = string.Empty;
            CookieOptions co = new CookieOptions();
            co.Expires = DateTime.Now.AddMinutes(-5);
            Response.Cookies.Append(key, value, co);
            return View("choose");
        }
        public IActionResult ReadCookie()
        {
            string key = "My_Cookie";
            var cookivalue = Request.Cookies[key];
            return View("Index");
        }
        public async Task<IActionResult> Auth(AuthViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Retrieve the verification code stored in session
                string storedVerificationCode = HttpContext.Session.GetString("VerificationCode");

                // Compare the verification code entered by the user with the stored one
                if (model.Code == storedVerificationCode)
                {
                    // Verification successful, proceed with authentication
                    // Clear the stored verification code from session
                    HttpContext.Session.Remove("VerificationCode");
                    await CreateStudentFromUnverified(model.email);
                    await RemoveUnverifiedUser(model.email);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid verification code.");
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }
        public async Task<IActionResult> CreateStudentFromUnverified(string email)
        {
            // Query the unverified table to retrieve user data based on email
            var unVerifiedUser = await _db.unverified.FirstOrDefaultAsync(u => u.Email == email);

            if (unVerifiedUser != null)
            {
                // Map the retrieved data to a new instance of the Student model
                var student = new Student
                {
                    Firstname = unVerifiedUser.Firstname,
                    Lastname = unVerifiedUser.Lastname,
                    Email = unVerifiedUser.Email,
                    Password = unVerifiedUser.Password
                };

                // Add the new Student instance to the students table
                _db.student.Add(student);

                // Save the changes to the database
                await _db.SaveChangesAsync();
                ViewBag.IsLoggedIn = true;
                return RedirectToAction("Index", "Home"); // Redirect to home page or another appropriate action
            }
            else
            {
                // Handle case where user with given email is not found in unverified table
                return RedirectToAction("Error"); // Redirect to an error page or another appropriate action
            }
        }
        public async Task<IActionResult> RemoveUnverifiedUser(string email)
        {
            // Query the unverified table to find the user based on email
            var unverifiedUser = await _db.unverified.FirstOrDefaultAsync(u => u.Email == email);

            if (unverifiedUser != null)
            {
                // Remove the user from the unverified table
                _db.unverified.Remove(unverifiedUser);

                // Save the changes to the database
                await _db.SaveChangesAsync();
                ViewBag.IsLoggedIn = true;
                return RedirectToAction("Index", "Home"); // Redirect to home page or another appropriate action
            }
            else
            {
                // Handle case where user with given email is not found in unverified table
                return RedirectToAction("Error"); // Redirect to an error page or another appropriate action
            }
        }
        public bool IsPasswordComplex(string password)
        {
            // Password must be at least 8 characters long and contain at least one special character, one capital letter, and one number
            var regex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$");
            return regex.IsMatch(password);
        }
        public bool IsValidEmail(string email)
        {
            try
            {
                var emailAddress = new MailAddress(email);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<IActionResult> Register(UnVerViewModel model)
        {
            if (ModelState.IsValid)
            {

                var existingUser = await _db.unverified.FirstOrDefaultAsync(s => s.Email == model.Email);

                if (existingUser != null || !IsValidEmail(model.Email) || !IsPasswordComplex(model.Password))
                {
                    // User already exists
                    ModelState.AddModelError(string.Empty, "An account with this email already exists.");
                    return View(model);
                }
                // Hash the password
                string hashedPassword = HashPassword(model.Password);
                // Create new student record
                var Unver = new UnVerified
                {
                    Email = model.Email,
                    Firstname = model.Firstname,
                    Lastname = model.Lastname,
                    Password = hashedPassword,
                    //StatusCode =codeGenerate()
                };
                /*var token = GenerateJwtToken(Unver.E_Mail);
                // Optionally, store the token in a secure HTTP-only cookie
                HttpContext.Response.Cookies.Append("jwt", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    // Other cookie options as needed
                });*/
                _db.unverified.Add(Unver);
                await _db.SaveChangesAsync();
                var emailSender = new EmailSender();

                //HttpContext.Session.SetInt32("SessionUserId", Unver.id);
                //HttpContext.Session.SetString("SessionUserName", Unver.FName);

                string verificationCode = codeGenerate();

                // Store the verification code in session
                HttpContext.Session.SetString("VerificationCode", verificationCode);
                await smth0(Unver.Email, "", "", verificationCode);
                return RedirectToAction("Auth", "Account");

            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid email address format. Please enter a valid email address.");
                return View(model);
            }
        }
        public string codeGenerate()
        {
            var buffer = new byte[sizeof(UInt64)];
            using (var cryptoRng = new RNGCryptoServiceProvider())
            {
                cryptoRng.GetBytes(buffer);
                var num = BitConverter.ToUInt64(buffer, 0);
                var code = num % 1000000; // Ensure it's a 6-digit number
                return code.ToString("D6"); // Format as a 6-character string
            }
        }
        //private string GenerateJwtToken(string userEmail)
        //{
        //    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my_secret_key_with_32_bytes_for_256_bits"));
        //    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        //    var token = new JwtSecurityToken(
        //        issuer: "CleverCamp",
        //        //audience: "http://www.CleverCamp.com",
        //        claims: new[] { new Claim(ClaimTypes.Email, userEmail) },
        //        expires: DateTime.Now.AddMinutes(5), // Token expiration time
        //        signingCredentials: credentials
        //    );

        //    return new JwtSecurityTokenHandler().WriteToken(token);
        //}
        //public IActionResult Verify(string verificationCode)
        //{
        //    // Get the generated verification code (from wherever you generated it)
        //    var generatedCode = codeGenerate(); // Replace with your actual generated code

        //    if (verificationCode == generatedCode)
        //    {
        //        // Verification successful
        //        return View("VerificationSuccess");
        //    }
        //    else
        //    {
        //        // Verification failed
        //        return View("VerificationFailure");
        //    }
        //}
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt());
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
    }
}
