using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Final8Net.Controllers
{
    [Authorize]
    public class SignCourseController : Controller
    {
        public IActionResult Java()
        {
            return View();
        }

        public IActionResult WebDesign()
        {
            return View();
        }

        public IActionResult DataStruct()
        {
            return View();
        }

        public IActionResult CPlusPlus()
        {
            return View();
        }
    }
}
