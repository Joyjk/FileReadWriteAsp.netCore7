using Microsoft.EntityFrameworkCore;
using WebApiReadFile7.Models;

namespace WebApiReadFile7.Dbcontext
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<Datalog> Datalogs { get; set; }
    }
}
