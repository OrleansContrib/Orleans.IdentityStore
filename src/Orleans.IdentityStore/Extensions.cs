﻿using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Orleans.IdentityStore;
using Orleans.IdentityStore.Grains;

namespace Orleans
{
    /// <summary>
    /// Grain Factory extensions
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Returns the role grain
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <typeparam name="TRole">The role type</typeparam>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">Role Id</param>
        /// <returns>The role grain</returns>
        public static IIdentityRoleGrain<TUser, TRole> Role<TUser, TRole>(this IGrainFactory factory, Guid id)
            where TUser : IdentityUser<Guid>
            where TRole : IdentityRole<Guid>
        {
            return factory.GetGrain<IIdentityRoleGrain<TUser, TRole>>(id);
        }

        /// <summary>
        /// Returns the role grain
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">Role Id</param>
        /// <returns>The role grain</returns>
        public static IIdentityRoleGrain<TUser, IdentityRole<Guid>> Role<TUser>(this IGrainFactory factory, Guid id)
            where TUser : IdentityUser<Guid>
        {
            return factory.GetGrain<IIdentityRoleGrain<TUser, IdentityRole<Guid>>>(id);
        }

        /// <summary>
        /// Returns the role grain
        /// </summary>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">Role Id</param>
        /// <returns>The role grain</returns>
        public static IIdentityRoleGrain<IdentityUser<Guid>, IdentityRole<Guid>> Role(this IGrainFactory factory, Guid id)
        {
            return factory.GetGrain<IIdentityRoleGrain<IdentityUser<Guid>, IdentityRole<Guid>>>(id);
        }

        /// <summary>
        /// Searches through all user
        /// </summary>
        /// <typeparam name="TUser"></typeparam>
        /// <param name="factory"></param>
        /// <param name="func"></param>
        /// <returns></returns>
        public static IAsyncEnumerable<IIdentityUserGrain<TUser, IdentityRole<Guid>>> SearchByUsername<TUser>(this IGrainFactory factory, Func<string, bool> func)
            where TUser : IdentityUser<Guid>
        {
            return factory.Search<IIdentityUserGrain<TUser, IdentityRole<Guid>>>(OrleansIdentityConstants.UsernameLookup, func);
        }

        /// <summary>
        /// Returns the user grain
        /// </summary>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">User Id</param>
        /// <returns>The user grain</returns>
        public static IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>> User(this IGrainFactory factory, Guid id)
        {
            return factory.GetGrain<IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>>>(id);
        }

        /// <summary>
        /// Returns the user grain
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">User Id</param>
        /// <returns>The user grain</returns>
        public static IIdentityUserGrain<TUser, IdentityRole<Guid>> User<TUser>(this IGrainFactory factory, Guid id)
            where TUser : IdentityUser<Guid>
        {
            return factory.GetGrain<IIdentityUserGrain<TUser, IdentityRole<Guid>>>(id);
        }

        /// <summary>
        /// Returns the user grain
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <typeparam name="TRole">The role type</typeparam>
        /// <param name="factory">Grain factory</param>
        /// <param name="id">User Id</param>
        /// <returns>The user grain</returns>
        public static IIdentityUserGrain<TUser, TRole> User<TUser, TRole>(this IGrainFactory factory, Guid id)
            where TUser : IdentityUser<Guid>
            where TRole : IdentityRole<Guid>
        {
            return factory.GetGrain<IIdentityUserGrain<TUser, TRole>>(id);
        }

        /// <summary>
        /// Finds a user by email
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <typeparam name="TRole">The role type</typeparam>
        /// <param name="factory">grain factory</param>
        /// <param name="email">The user's email</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<TUser, TRole>> UserByEmail<TUser, TRole>(this IGrainFactory factory, string email, ILookupNormalizer normalizer = null)
            where TUser : IdentityUser<Guid>
            where TRole : IdentityRole<Guid>
        {
            return factory.Find<IIdentityUserGrain<TUser, TRole>>(OrleansIdentityConstants.EmailLookup, normalizer?.NormalizeEmail(email) ?? email.ToUpperInvariant());
        }

        /// <summary>
        /// Finds a user by email
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <param name="factory">grain factory</param>
        /// <param name="email">The user's email</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<TUser, IdentityRole<Guid>>> UserByEmail<TUser>(this IGrainFactory factory, string email, ILookupNormalizer normalizer = null)
            where TUser : IdentityUser<Guid>
        {
            return factory.Find<IIdentityUserGrain<TUser, IdentityRole<Guid>>>(OrleansIdentityConstants.EmailLookup, normalizer?.NormalizeEmail(email) ?? email.ToUpperInvariant());
        }

        /// <summary>
        /// Finds a user by email
        /// </summary>
        /// <param name="factory">grain factory</param>
        /// <param name="email">The user's email</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>>> UserByEmail(this IGrainFactory factory, string email, ILookupNormalizer normalizer = null)
        {
            return factory.Find<IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>>>(OrleansIdentityConstants.EmailLookup, normalizer?.NormalizeEmail(email) ?? email.ToUpperInvariant());
        }

        /// <summary>
        /// Finds a user by username
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <typeparam name="TRole">The role type</typeparam>
        /// <param name="factory">grain factory</param>
        /// <param name="userName">The username</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<TUser, TRole>> UserByUsername<TUser, TRole>(this IGrainFactory factory, string userName, ILookupNormalizer normalizer = null)
            where TUser : IdentityUser<Guid>
            where TRole : IdentityRole<Guid>
        {
            return factory.Find<IIdentityUserGrain<TUser, TRole>>(OrleansIdentityConstants.UsernameLookup, normalizer?.NormalizeEmail(userName) ?? userName.ToUpperInvariant());
        }

        /// <summary>
        /// Finds a user by username
        /// </summary>
        /// <param name="factory">grain factory</param>
        /// <param name="userName">The username</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>>> UserByUsername(this IGrainFactory factory, string userName, ILookupNormalizer normalizer = null)
        {
            return factory.Find<IIdentityUserGrain<IdentityUser<Guid>, IdentityRole<Guid>>>(OrleansIdentityConstants.UsernameLookup, normalizer?.NormalizeEmail(userName) ?? userName.ToUpperInvariant());
        }

        /// <summary>
        /// Finds a user by username
        /// </summary>
        /// <typeparam name="TUser">The user type</typeparam>
        /// <param name="factory">grain factory</param>
        /// <param name="userName">The username</param>
        /// <param name="normalizer">
        /// The normalize to user, if none is provided, the default <see
        /// cref="UpperInvariantLookupNormalizer"/> will be used
        /// </param>
        /// <returns>The user grain</returns>
        public static Task<IIdentityUserGrain<TUser, IdentityRole<Guid>>> UserByUsername<TUser>(this IGrainFactory factory, string userName, ILookupNormalizer normalizer = null)
            where TUser : IdentityUser<Guid>
        {
            return factory.Find<IIdentityUserGrain<TUser, IdentityRole<Guid>>>(OrleansIdentityConstants.UsernameLookup, normalizer?.NormalizeEmail(userName) ?? userName.ToUpperInvariant());
        }

        internal static IIdentityClaimGrainInternal GetGrain(this IGrainFactory factory, Claim claim)
        {
            return factory.GetGrain<IIdentityClaimGrainInternal>($"{claim.Type}-{claim.Value}");
        }

        internal static IIdentityClaimGrainInternal GetGrain(this IGrainFactory factory, IdentityUserClaim<Guid> claim)
        {
            return factory.GetGrain<IIdentityClaimGrainInternal>($"{claim.ClaimType}-{claim.ClaimValue}");
        }
    }
}
