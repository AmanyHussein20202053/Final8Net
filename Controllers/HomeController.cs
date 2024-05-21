using Final8Net.Data;
using Final8Net.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Final8Net.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _db;
        public HomeController(ILogger<HomeController> logger, ApplicationDbContext db)
        {
            _db = db;
            _logger = logger;
        }
        public IActionResult Index()
        {
            ////visits counter
            //var visitString = Request.Cookies["visits"];
            //int visits = 0;
            //int.TryParse(visitString, out visits);
            //visits++;
            //CookieOptions options= new CookieOptions();
            //options.Secure = true;  
            //options.Expires= DateTime.Now.AddDays(365);
            //Response.Cookies.Append("visits", visits.ToString(),options);
            //ViewBag.Visits = visits;
            var student = _db.student.FirstOrDefault();
            //if (HttpContext.Session.GetInt32("SessionUserId") != null && HttpContext.Session.GetString("SessionUserName") !=null)
            //{
            //}
            return View();
        }
        public IActionResult Courses()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult Profile()
        {
            return View();
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        public IActionResult CreateCookie()
        {
            string key = "My_Cookie";
            string value = "UniqueCookie";
            CookieOptions co = new CookieOptions();
            co.Expires = DateTime.Now.AddMinutes(1);
            Response.Cookies.Append(key, value, co);

            return View("Index");
        }
        public IActionResult ReadCookie()
        {
            string key = "My_Cookie";
            var cookivalue = Request.Cookies[key];
            return View("Index");
        }

        public IActionResult RemoveCookie()
        {
            string key = "My_Cookie";
            string value = string.Empty;
            CookieOptions co = new CookieOptions();
            co.Expires = DateTime.Now.AddMinutes(-1);
            Response.Cookies.Append(key, value, co);
            return View("choose");
        }
    }
}
