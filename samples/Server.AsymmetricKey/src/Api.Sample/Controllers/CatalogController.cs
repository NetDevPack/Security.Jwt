using System.Collections.Generic;
using System.Linq;
using Api.Sample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Api.Sample.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/catalog")]
    public class CatalogController : ControllerBase
    {
        [HttpGet("itens")]
        public IEnumerable<Product> Index()
        {
            var products = new List<Product>();

            for (var i = 1; i < 5; i++)
            {
                products.Add(new Product
                {
                    Name = $"Product {i}",
                    Description = "Nice description",
                    Image = $"product{i}.jpg",
                    Price = 50
                });
            }

            return products;
        }

        [Authorize]
        public class IdentityController : ControllerBase
        {
            public IActionResult Get()
            {
                return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
            }
        }
    }
}
