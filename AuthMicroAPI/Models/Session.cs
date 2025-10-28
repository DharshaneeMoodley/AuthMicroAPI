using AuthMicroAPI.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthMicroAPI.Models
{
    [Table("Sessions")]
    public class Session
    {
        [Key]
        [MaxLength(255)]
        public string SessionId { get; set; } = string.Empty;

        [Required]
        public int UserId { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.Now;

        [Required]
        public DateTime ExpiryDate { get; set; }

        public bool IsActive { get; set; } = true;

        [MaxLength(50)]
        public string? IPAddress { get; set; }

        [MaxLength(500)]
        public string? UserAgent { get; set; }

        // Navigation property
        [ForeignKey("UserId")]
        public virtual User User { get; set; } = null!;
    }
}