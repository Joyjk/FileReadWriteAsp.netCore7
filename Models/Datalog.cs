using System.ComponentModel.DataAnnotations;

namespace WebApiReadFile7.Models
{
    public class Datalog
    {
        public int Id { get; set; }
        public string FileName { get; set; }
        public string RequestJson { get; set; }
    }
}
