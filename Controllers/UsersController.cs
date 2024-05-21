using Microsoft.AspNetCore.Mvc;

namespace Final8Net.Controllers
{
    public class UsersController : Controller
    {
        public IActionResult User()
        {
            return View();
        }
    }
}
