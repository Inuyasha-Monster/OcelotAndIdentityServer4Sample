using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityIdsServer.Data;
using IdentityIdsServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityIdsServer
{
    public class SeedData
    {
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            Console.WriteLine("Seeding database...");

            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                scope.ServiceProvider.GetService<ApplicationDbContext>().Database.Migrate();
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                var userRoleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();

                userRoleManager.CreateAsync(new IdentityRole("administrator")).Wait();

                var user = new ApplicationUser() { Age = 24, Avator = "fuck.com", UserName = "djlnet", NormalizedUserName = "djlnet", Email = "394922860@qq.com", NormalizedEmail = "394922860@qq.com" };

                userManager.CreateAsync(user, "111111").Wait();

                userManager.AddToRoleAsync(user, "administrator").Wait();
            }

            Console.WriteLine("Done seeding database.");
            Console.WriteLine();
        }
    }
}
