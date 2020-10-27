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
    /// Identity Role grain
    /// </summary>
    /// <typeparam name="TUser">The user type</typeparam>
    /// <typeparam name="TRole">The role type</typeparam>
    public interface IIdentityRoleGrain<TUser, TRole> : IGrainWithGuidKey
        where TUser : IdentityUser<Guid>
        where TRole : IdentityRole<Guid>
    {
        /// <summary>
        /// Adds a claim to the role
        /// </summary>
        /// <param name="claim">The claim to add</param>
        Task AddClaim(IdentityRoleClaim<Guid> claim);

        /// <summary>
        /// Adds a user to the role
        /// </summary>
        /// <param name="id">The user to add</param>
        Task AddUser(Guid id);

        /// <summary>
        /// Creates the role
        /// </summary>
        /// <param name="role">The role to create</param>
        /// <returns>Result of the operations</returns>
        Task<IdentityResult> Create(TRole role);

        /// <summary>
        /// Delete the role
        /// </summary>
        Task<IdentityResult> Delete();

        /// <summary>
        /// Gets the role
        /// </summary>
        /// <returns>the role</returns>
        [AlwaysInterleave]
        Task<TRole> Get();

        /// <summary>
        /// Gets all the claims
        /// </summary>
        /// <returns>The list of claims</returns>
        [AlwaysInterleave]
        Task<IList<IdentityRoleClaim<Guid>>> GetClaims();

        /// <summary>
        /// Gets the users associated with this role
        /// </summary>
        /// <returns>A list of user ids associated with this role</returns>
        [AlwaysInterleave]
        Task<IList<Guid>> GetUsers();

        /// <summary>
        /// Removes a claim from this role
        /// </summary>
        /// <param name="claim">The claim to remove</param>
        Task RemoveClaim(Claim claim);

        /// <summary>
        /// Removes a user from this role
        /// </summary>
        /// <param name="id">The user to remove</param>
        Task RemoveUser(Guid id);

        /// <summary>
        /// Updates the role
        /// </summary>
        /// <param name="role">The updated role</param>
        /// <returns>Result of the operations</returns>
        Task<IdentityResult> Update(TRole role);
    }

    internal class IdentityRoleGrain<TUser, TRole> : Grain, IIdentityRoleGrain<TUser, TRole>
        where TUser : IdentityUser<Guid>
        where TRole : IdentityRole<Guid>
    {
        private readonly IPersistentState<RoleGrainState<TRole>> _data;
        private readonly ILookupNormalizer _normalizer;
        private Guid _id;

        public IdentityRoleGrain(
            ILookupNormalizer normalizer,
            [PersistentState("IdentityRole", OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<RoleGrainState<TRole>> data)
        {
            _data = data;
            _normalizer = normalizer;
        }

        private bool Exists => _data.State?.Role != null;

        public Task AddClaim(IdentityRoleClaim<Guid> claim)
        {
            if (Exists && claim != null)
            {
                _data.State.Claims.Add(claim);
                return _data.WriteStateAsync();
            }

            return Task.CompletedTask;
        }

        public Task AddUser(Guid id)
        {
            if (Exists && _data.State.Users.Add(id))
                return _data.WriteStateAsync();

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> Create(TRole role)
        {
            if (Exists || string.IsNullOrEmpty(role.Name))
            {
                return IdentityResult.Failed();
            }

            // Normalize name
            role.NormalizedName = _normalizer.NormalizeName(role.Name);

            if ((await GrainFactory.GetGrain<IIdentityRoleByNameGrain>(role.NormalizedName).GetId()) != null)
                return IdentityResult.Failed();

            _data.State.Role = role;
            await GrainFactory.GetGrain<IIdentityRoleByNameGrain>(role.NormalizedName).SetId(role.Id);
            await _data.WriteStateAsync();

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> Delete()
        {
            if (_data.State.Role == null)
                return IdentityResult.Failed();

            await GrainFactory.GetGrain<IIdentityRoleByNameGrain>(_data.State.Role.NormalizedName).ClearId();
            await Task.WhenAll(_data.State.Users.Select(u => GrainFactory.GetGrain<IIdentityUserGrain<TUser, TRole>>(u).RemoveRole(_id, false)));
            await _data.ClearStateAsync();

            return IdentityResult.Success;
        }

        public Task<TRole> Get()
        {
            return Task.FromResult(_data.State.Role);
        }

        public Task<IList<IdentityRoleClaim<Guid>>> GetClaims()
        {
            if (Exists)
            {
                return Task.FromResult<IList<IdentityRoleClaim<Guid>>>(_data.State.Claims);
            }

            return Task.FromResult<IList<IdentityRoleClaim<Guid>>>(null);
        }

        public Task<IList<Guid>> GetUsers()
        {
            return Task.FromResult<IList<Guid>>(_data.State.Users.ToList());
        }

        public override Task OnActivateAsync()
        {
            _id = this.GetPrimaryKey();
            return Task.CompletedTask;
        }

        public Task RemoveClaim(Claim claim)
        {
            if (Exists)
            {
                var writeRequired = false;
                foreach (var m in _data.State.Claims.Where(rc => rc.ClaimValue == claim.Value && rc.ClaimType == claim.Type))
                {
                    writeRequired = true;
                    _data.State.Claims.Remove(m);
                }

                if (writeRequired)
                    return _data.WriteStateAsync();
            }

            return Task.CompletedTask;
        }

        public Task RemoveUser(Guid id)
        {
            if (_data.State.Users.Remove(id))
                return _data.WriteStateAsync();

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> Update(TRole role)
        {
            if (!Exists || string.IsNullOrEmpty(role.Name))
                return IdentityResult.Failed();

            // Normalize name
            role.NormalizedName = _normalizer.NormalizeName(role.Name);

            if ((await GrainFactory.GetGrain<IIdentityRoleByNameGrain>(role.NormalizedName).GetId()) != null)
                return IdentityResult.Failed();

            _data.State.Role = role;
            await _data.WriteStateAsync();

            return IdentityResult.Success;
        }
    }

    internal class RoleGrainState<TRole>
    {
        public List<IdentityRoleClaim<Guid>> Claims { get; set; } = new List<IdentityRoleClaim<Guid>>();
        public TRole Role { get; set; }
        public HashSet<Guid> Users { get; set; } = new HashSet<Guid>();
    }
}