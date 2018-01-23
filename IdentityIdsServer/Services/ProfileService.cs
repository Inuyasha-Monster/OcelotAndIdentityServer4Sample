using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityIdsServer.Models;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;

namespace IdentityIdsServer.Services
{
    public class ProfileService : IProfileService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ProfileService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }


        private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, await _userManager.GetUserIdAsync(user)),
                new Claim(JwtClaimTypes.Name, await _userManager.GetUserNameAsync(user))
            };

            if (_userManager.SupportsUserEmail)
            {
                var email = await _userManager.GetEmailAsync(user);
                if (!string.IsNullOrWhiteSpace(email))
                {
                    claims.AddRange(new[]
                    {
                        new Claim(JwtClaimTypes.Email, email),
                        new Claim(JwtClaimTypes.EmailVerified,
                            await _userManager.IsEmailConfirmedAsync(user) ? "true" : "false", ClaimValueTypes.Boolean)
                    });
                }
            }

            if (_userManager.SupportsUserPhoneNumber)
            {
                var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
                if (!string.IsNullOrWhiteSpace(phoneNumber))
                {
                    claims.AddRange(new[]
                    {
                        new Claim(JwtClaimTypes.PhoneNumber, phoneNumber),
                        new Claim(JwtClaimTypes.PhoneNumberVerified,
                            await _userManager.IsPhoneNumberConfirmedAsync(user) ? "true" : "false", ClaimValueTypes.Boolean)
                    });
                }
            }

            if (_userManager.SupportsUserClaim)
            {
                claims.AddRange(await _userManager.GetClaimsAsync(user));
            }

            if (_userManager.SupportsUserRole)
            {
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));
            }

            return claims;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var user = await _userManager.FindByIdAsync(context.Subject.GetSubjectId());

            var claims = await GetClaimsAsync(user);

            claims = claims.Where(claim => context.RequestedClaimTypes.Contains(claim.Type)).ToList();

            context.IssuedClaims = claims;
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (context.Subject == null) throw new ArgumentNullException(nameof(context.Subject));

            context.IsActive = false;

            var subject = context.Subject;
            var user = await _userManager.FindByIdAsync(context.Subject.GetSubjectId());

            if (user != null)
            {
                var securityStampChanged = false;

                if (_userManager.SupportsUserSecurityStamp)
                {
                    var securityStamp = (
                        from claim in subject.Claims
                        where claim.Type == "security_stamp"
                        select claim.Value
                    ).SingleOrDefault();

                    if (securityStamp != null)
                    {
                        var latestSecurityStamp = await _userManager.GetSecurityStampAsync(user);
                        securityStampChanged = securityStamp != latestSecurityStamp;
                    }
                }

                context.IsActive =
                    !securityStampChanged &&
                    !await _userManager.IsLockedOutAsync(user);
            }
        }
    }
}
