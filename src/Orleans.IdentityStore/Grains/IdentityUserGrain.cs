using Microsoft.AspNetCore.Identity;
using Orleans.Concurrency;
using Orleans.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Orleans.IdentityStore.Grains
{
    /// <summary>
    /// Identity user grain
    /// </summary>
    /// <typeparam name="TUser">The user type</typeparam>
    /// <typeparam name="TRole">The role type</typeparam>
    public interface IIdentityUserGrain<TUser, TRole> : IGrainWithGuidKey
        where TUser : IdentityUser<Guid>
        where TRole : IdentityRole<Guid>
    {
        /// <summary>
        /// Add claims to user
        /// </summary>
        /// <param name="claims">The list of claims to add</param>
        Task AddClaims(IList<IdentityUserClaim<Guid>> claims);

        /// <summary>
        /// Add a login to user
        /// </summary>
        /// <param name="login">The login to add</param>
        Task AddLogin(IdentityUserLogin<Guid> login);

        /// <summary>
        /// Add a token to user
        /// </summary>
        /// <param name="token">The token to add</param>
        Task AddToken(IdentityUserToken<Guid> token);

        /// <summary>
        /// Adds a role to a user
        /// </summary>
        /// <param name="roleId">The id of the role to add</param>
        Task AddToRole(Guid roleId);

        /// <summary>
        /// Check if user has role
        /// </summary>
        /// <param name="id">The role id</param>
        /// <returns>true if the user has role, false otherwise</returns>
        [AlwaysInterleave]
        Task<bool> ContainsRole(Guid id);

        /// <summary>
        /// Creates the user
        /// </summary>
        /// <param name="user">The user data</param>
        /// <returns>Result of the operations</returns>
        Task<IdentityResult> Create(TUser user);

        /// <summary>
        /// Deletes user
        /// </summary>
        Task<IdentityResult> Delete();

        /// <summary>
        /// Get the user
        /// </summary>
        /// <returns>The user</returns>
        [AlwaysInterleave]
        Task<TUser> Get();

        /// <summary>
        /// Get the claims associated with this user
        /// </summary>
        /// <returns>A list of claims</returns>
        Task<IList<IdentityUserClaim<Guid>>> GetClaims();

        /// <summary>
        /// Gets the login for the current usr
        /// </summary>
        /// <param name="loginProvider">The login provider</param>
        /// <param name="providerKey">The login key</param>
        /// <returns>The loging</returns>
        [AlwaysInterleave]
        Task<IdentityUserLogin<Guid>> GetLogin(string loginProvider, string providerKey);

        /// <summary>
        /// Gets all the logins for the current user
        /// </summary>
        /// <returns>A list of logins</returns>
        [AlwaysInterleave]
        Task<IList<IdentityUserLogin<Guid>>> GetLogins();

        /// <summary>
        /// Gets the roles for the current user
        /// </summary>
        /// <returns>A list of role names</returns>
        [AlwaysInterleave]
        Task<IList<string>> GetRoles();

        /// <summary>
        /// Gets a token
        /// </summary>
        /// <param name="loginProvider">The login provider</param>
        /// <param name="name">The name</param>
        /// <returns>The user token</returns>
        [AlwaysInterleave]
        Task<IdentityUserToken<Guid>> GetToken(string loginProvider, string name);

        /// <summary>
        /// Remove claims for current user
        /// </summary>
        /// <param name="claims">A list of claims to remove</param>
        Task RemoveClaims(IList<Claim> claims);

        /// <summary>
        /// Removes a login from the current user
        /// </summary>
        /// <param name="loginProvider">The login provider</param>
        /// <param name="providerKey">The login key</param>
        Task RemoveLogin(string loginProvider, string providerKey);

        /// <summary>
        /// Removes a role from the current user
        /// </summary>
        /// <param name="id">The ID of the role to remove</param>
        /// <param name="updateRoleGrain">if true, will remove user from role grain</param>
        Task RemoveRole(Guid id, bool updateRoleGrain);

        /// <summary>
        /// Removes token from user
        /// </summary>
        /// <param name="token">the token to remove</param>
        Task RemoveToken(IdentityUserToken<Guid> token);

        /// <summary>
        /// Replaces claims for the current user
        /// </summary>
        /// <param name="claim">The claim to replace</param>
        /// <param name="newClaim">The new claim</param>
        Task ReplaceClaims(Claim claim, Claim newClaim);

        /// <summary>
        /// Updates the current user
        /// </summary>
        /// <param name="user">The updated user</param>
        /// <returns>Result of the operations</returns>
        Task<IdentityResult> Update(TUser user);
    }

    internal class IdentityUserGrain<TUser, TRole> :
            Grain, IIdentityUserGrain<TUser, TRole>
        where TUser : IdentityUser<Guid>, new()
        where TRole : IdentityRole<Guid>, new()
    {
        private readonly IPersistentState<IdentityUserGrainState<TUser, TRole>> _data;
        private readonly IdentityErrorDescriber _errorDescriber = new IdentityErrorDescriber();
        private readonly ILookupNormalizer _normalizer;
        private Guid _id;

        public IdentityUserGrain(
            ILookupNormalizer normalizer,
            [PersistentState("IdentityUser", OrleansIdentityConstants.OrleansStorageProvider)]
        IPersistentState<IdentityUserGrainState<TUser, TRole>> data)
        {
            _data = data;
            _normalizer = normalizer;
        }

        private bool Exists => _data.State?.User != null;

        public Task AddClaims(IList<IdentityUserClaim<Guid>> claims)
        {
            if (Exists && claims?.Count > 0)
            {
                var tasks = new List<Task>();
                foreach (var c in claims)
                {
                    _data.State.Claims.Add(c);
                    tasks.Add(GrainFactory.GetGrain(c).AddUserId(_id));
                }
                tasks.Add(_data.WriteStateAsync());
                return Task.WhenAll(tasks);
            }

            return Task.CompletedTask;
        }

        public Task AddLogin(IdentityUserLogin<Guid> login)
        {
            if (Exists && login != null)
            {
                _data.State.Logins.Add(login);
                return _data.WriteStateAsync();
            }

            return Task.CompletedTask;
        }

        public Task AddToken(IdentityUserToken<Guid> token)
        {
            if (Exists && token != null)
            {
                _data.State.Tokens.Add(token);
                return _data.WriteStateAsync();
            }

            return Task.CompletedTask;
        }

        public Task AddToRole(Guid roleId)
        {
            if (Exists && _data.State.Roles.Add(roleId))
            {
                return Task.WhenAll(
                    GrainFactory.GetGrain<IIdentityRoleGrain<TUser, TRole>>(roleId).AddUser(_id),
                    _data.WriteStateAsync());
            }

            return Task.CompletedTask;
        }

        public Task<bool> ContainsRole(Guid id)
        {
            return Task.FromResult(Exists && _data.State.Roles.Contains(id));
        }

        public async Task<IdentityResult> Create(TUser user)
        {
            if (Exists)
                return IdentityResult.Failed(_errorDescriber.LoginAlreadyAssociated());
            if (string.IsNullOrEmpty(user.Email))
                return IdentityResult.Failed(_errorDescriber.InvalidEmail(user.Email));
            if (string.IsNullOrEmpty(user.UserName))
                return IdentityResult.Failed(_errorDescriber.InvalidUserName(user.UserName));

            // Make sure to set normalized username and email
            user.NormalizedEmail = _normalizer.NormalizeEmail(user.Email);
            user.NormalizedUserName = _normalizer.NormalizeName(user.UserName);

            if ((await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(user.NormalizedEmail).GetId()) != null)
                return IdentityResult.Failed(_errorDescriber.DuplicateEmail(user.Email));
            if ((await GrainFactory.GetGrain<IIdentityUserByNameGrain>(user.NormalizedUserName).GetId()) != null)
                return IdentityResult.Failed(_errorDescriber.DuplicateUserName(user.UserName));

            _data.State.User = user;

            await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(user.NormalizedEmail).SetId(user.Id);
            await GrainFactory.GetGrain<IIdentityUserByNameGrain>(user.NormalizedUserName).SetId(user.Id);
            await _data.WriteStateAsync();

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> Delete()
        {
            if (_data.State.User == null)
                return IdentityResult.Failed(_errorDescriber.DefaultError());

            await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(_data.State.User.NormalizedEmail).ClearId();
            await GrainFactory.GetGrain<IIdentityUserByNameGrain>(_data.State.User.NormalizedUserName).ClearId();
            await Task.WhenAll(_data.State.Roles.Select(r => GrainFactory.GetGrain<IIdentityRoleGrain<TUser, TRole>>(r).RemoveUser(_id)));
            await _data.ClearStateAsync();

            return IdentityResult.Success;
        }

        public Task<TUser> Get()
        {
            return Task.FromResult(_data.State.User);
        }

        public Task<IList<IdentityUserClaim<Guid>>> GetClaims()
        {
            if (Exists)
            {
                return Task.FromResult<IList<IdentityUserClaim<Guid>>>(_data.State.Claims);
            }
            return Task.FromResult<IList<IdentityUserClaim<Guid>>>(null);
        }

        public Task<IdentityUserLogin<Guid>> GetLogin(string loginProvider, string providerKey)
        {
            if (Exists)
            {
                return Task.FromResult(_data.State.Logins.Find(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey));
            }
            return Task.FromResult<IdentityUserLogin<Guid>>(null);
        }

        public Task<IList<IdentityUserLogin<Guid>>> GetLogins()
        {
            if (Exists)
            {
                return Task.FromResult<IList<IdentityUserLogin<Guid>>>(_data.State.Logins);
            }
            return Task.FromResult<IList<IdentityUserLogin<Guid>>>(null);
        }

        public async Task<IList<string>> GetRoles()
        {
            if (Exists)
            {
                return (await Task.WhenAll(_data.State.Roles.Select(r => GrainFactory.GetGrain<IIdentityRoleGrain<TUser, TRole>>(r).Get())))
                    .Select(r => r.Name)
                    .ToList();
            }

            return null;
        }

        public Task<IdentityUserToken<Guid>> GetToken(string loginProvider, string name)
        {
            if (Exists)
            {
                return Task.FromResult(_data.State.Tokens.Find(t => t.LoginProvider == loginProvider && t.Name == name));
            }

            return Task.FromResult<IdentityUserToken<Guid>>(null);
        }

        public override Task OnActivateAsync()
        {
            _id = this.GetPrimaryKey();
            return Task.CompletedTask;
        }

        public Task RemoveClaims(IList<Claim> claims)
        {
            var writeRequired = false;
            var tasks = new List<Task>();
            foreach (var c in claims)
            {
                foreach (var m in _data.State.Claims.Where(uc => uc.ClaimValue == c.Value && uc.ClaimType == c.Type))
                {
                    writeRequired = true;
                    _data.State.Claims.Remove(m);
                    tasks.Add(GrainFactory.GetGrain(m).RemoveUserId(_id));
                }
            }

            if (writeRequired)
                tasks.Add(_data.WriteStateAsync());

            return Task.WhenAll(tasks);
        }

        public Task RemoveLogin(string loginProvider, string providerKey)
        {
            if (Exists)
            {
                var loginToRemove = _data.State.Logins.Find(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
                if (loginToRemove != null)
                {
                    _data.State.Logins.Remove(loginToRemove);

                    return Task.WhenAll(_data.WriteStateAsync(), GrainFactory.GetGrain(loginToRemove).ClearId());
                }
            }

            return Task.CompletedTask;
        }

        public async Task RemoveRole(Guid id, bool updateRoleGrain)
        {
            if (Exists && _data.State.Roles.Remove(id))
            {
                if (updateRoleGrain)
                {
                    await GrainFactory.GetGrain<IIdentityRoleGrain<TUser, TRole>>(id).RemoveUser(_id);
                }

                await _data.WriteStateAsync();
            }
        }

        public Task RemoveToken(IdentityUserToken<Guid> token)
        {
            if (Exists)
            {
                var tokensToRemove = _data.State.Tokens.Find(t => t.LoginProvider == token.LoginProvider && t.Name == token.Name);
                if (tokensToRemove != null)
                {
                    _data.State.Tokens.Remove(tokensToRemove);
                    return _data.WriteStateAsync();
                }
            }

            return Task.CompletedTask;
        }

        public Task ReplaceClaims(Claim claim, Claim newClaim)
        {
            var matchedClaims = _data.State.Claims
                .Where(uc => uc.UserId.Equals(_id) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type);

            if (matchedClaims.Any())
            {
                var tasks = new List<Task>();
                foreach (var c in matchedClaims)
                {
                    tasks.Add(GrainFactory.GetGrain(c).RemoveUserId(_id));
                    c.ClaimValue = newClaim.Value;
                    c.ClaimType = newClaim.Type;
                    tasks.Add(GrainFactory.GetGrain(c).AddUserId(_id));
                }

                tasks.Add(_data.WriteStateAsync());

                return Task.WhenAll(tasks);
            }

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> Update(TUser user)
        {
            if (_data.State.User == null)
                return IdentityResult.Failed(_errorDescriber.DefaultError());
            if (string.IsNullOrEmpty(user.Email))
                return IdentityResult.Failed(_errorDescriber.InvalidEmail(user.Email));
            if (string.IsNullOrEmpty(user.UserName))
                return IdentityResult.Failed(_errorDescriber.InvalidUserName(user.UserName));

            // Make sure to set normalized username and email
            user.NormalizedEmail = _normalizer.NormalizeEmail(user.Email);
            user.NormalizedUserName = _normalizer.NormalizeName(user.UserName);

            // Make sure the new user name and email aren't already in use
            if (user.NormalizedEmail != _data.State.User.NormalizedEmail &&
                (await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(user.NormalizedEmail).GetId()) != null)
            {
                return IdentityResult.Failed(_errorDescriber.DuplicateEmail(user.Email));
            }

            if (user.NormalizedUserName != _data.State.User.NormalizedUserName &&
                (await GrainFactory.GetGrain<IIdentityUserByNameGrain>(user.NormalizedUserName).GetId()) != null)
            {
                return IdentityResult.Failed(_errorDescriber.DuplicateUserName(user.UserName));
            }

            if (user.NormalizedEmail != _data.State.User.NormalizedEmail)
            {
                await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(_data.State.User.NormalizedEmail).ClearId();
                await GrainFactory.GetGrain<IIdentityUserByEmailGrain>(user.NormalizedEmail).SetId(user.Id);
            }

            if (user.NormalizedUserName != _data.State.User.NormalizedUserName)
            {
                await GrainFactory.GetGrain<IIdentityUserByNameGrain>(_data.State.User.NormalizedUserName).ClearId();
                await GrainFactory.GetGrain<IIdentityUserByNameGrain>(user.NormalizedUserName).SetId(user.Id);
            }

            _data.State.User = user;
            await _data.WriteStateAsync();

            return IdentityResult.Success;
        }
    }

    internal class IdentityUserGrainState<TUser, TRole>
            where TUser : IdentityUser<Guid>, new()
        where TRole : IdentityRole<Guid>, new()
    {
        public List<IdentityUserClaim<Guid>> Claims { get; set; } = new List<IdentityUserClaim<Guid>>();
        public List<IdentityUserLogin<Guid>> Logins { get; set; } = new List<IdentityUserLogin<Guid>>();
        public HashSet<Guid> Roles { get; set; } = new HashSet<Guid>();
        public List<IdentityUserToken<Guid>> Tokens { get; set; } = new List<IdentityUserToken<Guid>>();
        public TUser User { get; set; }
    }
}