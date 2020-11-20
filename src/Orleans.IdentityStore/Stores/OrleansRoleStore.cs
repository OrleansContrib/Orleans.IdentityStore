using Microsoft.AspNetCore.Identity;
using Orleans.IdentityStore.Grains;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Orleans.IdentityStore.Stores
{
    /// <summary>
    /// A role store backed by Orleans
    /// </summary>
    /// <typeparam name="TUser">The user type</typeparam>
    /// <typeparam name="TRole">The role type</typeparam>
    public class OrleansRoleStore<TUser, TRole> : IRoleClaimStore<TRole>
        where TUser : IdentityUser<Guid>
        where TRole : IdentityRole<Guid>
    {
        private readonly IClusterClient _client;
        private bool _disposed;

        /// <summary>
        /// Creates the role store
        /// </summary>
        /// <param name="client">Orleans cluster client</param>
        public OrleansRoleStore(IClusterClient client)

        {
            _client = client;
        }

        /// <summary>
        /// Adds the <paramref name="claim"/> given to the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="claim">The claim to add to the role.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).AddClaim(new IdentityRoleClaim<Guid>
            {
                RoleId = role.Id,
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            });
        }

        /// <summary>
        /// Creates a new role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to create in the store.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the
        /// asynchronous query.
        /// </returns>
        public Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (role.Id == default)
            {
                role.Id = Guid.NewGuid();
            }

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).Create(role);
        }

        /// <summary>
        /// Deletes a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the
        /// asynchronous query.
        /// </returns>
        public Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).Delete();
        }

        /// <summary>
        /// Dispose the stores
        /// </summary>
        public void Dispose()
        {
            _disposed = true;
        }

        /// <summary>
        /// Finds the role who has the specified ID as an asynchronous operation.
        /// </summary>
        /// <param name="roleId">The role ID to look for.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(Guid.Parse(roleId)).Get();
        }

        /// <summary>
        /// Finds the role who has the specified normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="normalizedRoleName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var grain = await _client.Find<IIdentityRoleGrain<TUser, TRole>>(OrleansIdentityConstants.RoleLookup, normalizedRoleName);

            if (grain != null)
            {
                return await grain.Get();
            }

            return null;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="role"/> as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose claims should be retrieved.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a role.</returns>
        public async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return (await _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).GetClaims())
                .Select(c => new Claim(c.ClaimType, c.ClaimValue))
                .ToList();
        }

        /// <summary>
        /// Get a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.NormalizedName);
        }

        /// <summary>
        /// Gets the ID for a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose ID should be returned.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the ID of the role.</returns>
        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.Id.ToString());
        }

        /// <summary>
        /// Gets the name of a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.Name);
        }

        /// <summary>
        /// Removes the <paramref name="claim"/> given from the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The role to remove the claim from.</param>
        /// <param name="claim">The claim to remove from the role.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).RemoveClaim(claim);
        }

        /// <summary>
        /// Set a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the name of a role in the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates a role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to update in the store.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> used to propagate notifications that the operation
        /// should be canceled.
        /// </param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the
        /// asynchronous query.
        /// </returns>
        public Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return _client.GetGrain<IIdentityRoleGrain<TUser, TRole>>(role.Id).Update(role);
        }

        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected virtual void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }
    }
}