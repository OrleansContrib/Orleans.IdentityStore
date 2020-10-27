using Microsoft.AspNetCore.Identity;
using Orleans.IdentityStore.Stores;
using Orleans.TestingHost;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Orleans.IdentityStore.Tests
{
    [Collection(ClusterCollection.Name)]
    public class StoreTests
    {
        private static readonly ILookupNormalizer normalizer = new UpperInvariantLookupNormalizer();
        private readonly TestCluster _cluster;

        public StoreTests(ClusterFixture fixture)
        {
            _cluster = fixture.Cluster;
        }

        [Fact]
        public async Task CanAddRole()
        {
            var userId = Guid.NewGuid();
            var roleId = Guid.NewGuid();
            var username = $"{userId}";
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };

            var store = GetSubject(out var roleStore);
            await roleStore.CreateAsync(new IdentityRole<Guid>
            {
                Id = roleId,
                Name = roleId.ToString(),
                NormalizedName = roleId.ToString()
            }, CancellationToken.None);

            await store.CreateAsync(user);
            await store.AddToRoleAsync(user, normalizer.NormalizeName(roleId.ToString()));

            var roleFromUser = await store.GetRolesAsync(user);
            var userInRole = await store.GetUsersInRoleAsync(normalizer.NormalizeName(roleId.ToString()));

            Assert.Single(roleFromUser);
            Assert.Single(userInRole);
        }

        [Fact]
        public async Task CanCreate2Users()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = $"{userId}@test.com",
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
                NormalizedUserName = $"{userId}"
            };

            var user2 = new IdentityUser<Guid>
            {
                Id = userId2,
                NormalizedEmail = $"{userId2}@test.com",
                Email = $"{userId2}@test.com",
                UserName = $"{userId2}",
                NormalizedUserName = $"{userId2}"
            };

            var store = GetSubject();

            var result = await store.CreateAsync(user);
            var result2 = await store.CreateAsync(user2);

            Assert.True(result.Succeeded);
            Assert.True(result2.Succeeded);
        }

        [Fact]
        public async Task CanCreateUserWithoutSettingId()
        {
            var username = $"{Guid.NewGuid()}";
            var user = new IdentityUser<Guid>
            {
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };

            var store = GetSubject();

            await store.CreateAsync(user);
            Assert.NotEqual(default, user.Id);

            var userById = await store.FindByIdAsync(user.Id.ToString());
            var userByName = await store.FindByEmailAsync(normalizer.NormalizeEmail(username + "@test.com"));

            Assert.NotNull(userById);
            Assert.NotNull(userByName);
            Assert.Equal(user.Id, userById.Id);
            Assert.Equal(user.Id, userByName.Id);
            Assert.Equal(user.Email, userById.Email);
            Assert.Equal(user.Email, userByName.Email);
        }

        [Fact]
        public async Task CanCreateUserWithSettingId()
        {
            var userId = Guid.NewGuid();
            var username = $"{userId}";
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };

            var store = GetSubject();

            await store.CreateAsync(user);
            Assert.Equal(userId, user.Id);

            var userById = await store.FindByIdAsync(user.Id.ToString());
            var userByName = await store.FindByEmailAsync(normalizer.NormalizeEmail(username + "@test.com"));

            Assert.NotNull(userById);
            Assert.NotNull(userByName);
            Assert.Equal(userId, userById.Id);
            Assert.Equal(userId, userByName.Id);
            Assert.Equal(user.Email, userById.Email);
            Assert.Equal(user.Email, userByName.Email);
        }

        [Fact]
        public async Task CanDeleteRole()
        {
            await Task.Delay(100);
            var userId = Guid.NewGuid();
            var roleId = Guid.NewGuid();
            var username = $"{userId}";
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };
            var role = new IdentityRole<Guid>
            {
                Id = roleId,
                Name = roleId.ToString(),
                NormalizedName = roleId.ToString()
            };

            var store = GetSubject(out var roleStore);
            await roleStore.CreateAsync(role, CancellationToken.None);

            await store.CreateAsync(user);
            await store.AddToRoleAsync(user, normalizer.NormalizeName(roleId.ToString()));
            var roleFromUser = await store.GetRolesAsync(user);
            var userInRole = await store.GetUsersInRoleAsync(normalizer.NormalizeName(roleId.ToString()));
            await roleStore.DeleteAsync(role, CancellationToken.None);
            var roleFromUser2 = await store.GetRolesAsync(user);
            var userInRole2 = await store.GetUsersInRoleAsync(normalizer.NormalizeName(roleId.ToString()));

            Assert.Single(roleFromUser);
            Assert.Single(userInRole);
            Assert.Empty(roleFromUser2);
            Assert.Empty(userInRole2);
        }

        [Fact]
        public async Task CanDeleteUser()
        {
            var userId = Guid.NewGuid();
            var username = $"{userId}";
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };

            var store = GetSubject();

            await store.CreateAsync(user);
            await store.DeleteAsync(user);

            var userById = await store.FindByIdAsync(user.Id.ToString());
            var userByName = await store.FindByEmailAsync(username + "@test.com");

            Assert.Null(userById);
            Assert.Null(userByName);
        }

        [Fact]
        public async Task CanDeleteUserWithRole()
        {
            await Task.Delay(100);
            var userId = Guid.NewGuid();
            var roleId = Guid.NewGuid();
            var username = $"{userId}";
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = username + "@test.com",
                Email = username + "@test.com",
                UserName = username,
                NormalizedUserName = username
            };
            var role = new IdentityRole<Guid>
            {
                Id = roleId,
                Name = roleId.ToString(),
                NormalizedName = roleId.ToString()
            };

            var store = GetSubject(out var roleStore);
            await roleStore.CreateAsync(role, CancellationToken.None);

            await store.CreateAsync(user);
            await store.AddToRoleAsync(user, normalizer.NormalizeName(roleId.ToString()));
            var roleFromUser = await store.GetRolesAsync(user);
            var userInRole = await store.GetUsersInRoleAsync(normalizer.NormalizeName(roleId.ToString()));
            await store.DeleteAsync(user);
            var roleFromUser2 = await store.GetRolesAsync(user);
            var userInRole2 = await store.GetUsersInRoleAsync(normalizer.NormalizeName(roleId.ToString()));

            Assert.Single(roleFromUser);
            Assert.Single(userInRole);
            Assert.Empty(roleFromUser2);
            Assert.Empty(userInRole2);
        }

        [Fact]
        public async Task CannotCreateUserWithSameEmail()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = $"{userId}@test.com",
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
                NormalizedUserName = $"{userId}"
            };

            var user2 = new IdentityUser<Guid>
            {
                Id = userId2,
                NormalizedEmail = $"{userId}@test.com",
                Email = $"{userId}@test.com",
                UserName = $"{userId2}",
                NormalizedUserName = $"{userId2}"
            };

            var store = GetSubject();

            var result = await store.CreateAsync(user);
            var result2 = await store.CreateAsync(user2);

            Assert.True(result.Succeeded);
            Assert.False(result2.Succeeded);
        }

        [Fact]
        public async Task CannotCreateUserWithSameId()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = $"{userId}@test.com",
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
                NormalizedUserName = $"{userId}"
            };

            var user2 = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = $"{userId2}@test.com",
                Email = $"{userId2}@test.com",
                UserName = $"{userId2}",
                NormalizedUserName = $"{userId2}"
            };

            var store = GetSubject();

            var result = await store.CreateAsync(user);
            var result2 = await store.CreateAsync(user2);

            Assert.True(result.Succeeded);
            Assert.False(result2.Succeeded);
        }

        [Fact]
        public async Task CannotCreateUserWithSameUserName()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                NormalizedEmail = $"{userId}@test.com",
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
                NormalizedUserName = $"{userId}"
            };

            var user2 = new IdentityUser<Guid>
            {
                Id = userId2,
                NormalizedEmail = $"{userId2}@test.com",
                Email = $"{userId2}@test.com",
                UserName = $"{userId}",
                NormalizedUserName = $"{userId}"
            };

            var store = GetSubject();

            var result = await store.CreateAsync(user);
            var result2 = await store.CreateAsync(user2);

            Assert.True(result.Succeeded);
            Assert.False(result2.Succeeded);
        }

        [Fact]
        public async Task CanUpdateEmail()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
            };

            var store = GetSubject();

            await store.CreateAsync(user);
            var userById = await store.FindByIdAsync(user.Id.ToString());
            var userByEmail = await store.FindByEmailAsync(normalizer.NormalizeEmail($"{userId}@test.com"));

            user.Email = $"{userId2}@test.com";
            await store.UpdateAsync(user);
            var userById2 = await store.FindByIdAsync(user.Id.ToString());
            var userByEmail2 = await store.FindByEmailAsync(normalizer.NormalizeEmail($"{userId}@test.com"));
            var userByEmail3 = await store.FindByEmailAsync(normalizer.NormalizeEmail($"{userId2}@test.com"));

            Assert.NotNull(userById);
            Assert.NotNull(userByEmail);
            Assert.NotNull(userById2);
            Assert.Null(userByEmail2);
            Assert.NotNull(userByEmail3);
        }

        [Fact]
        public async Task CanUpdateUserName()
        {
            var userId = Guid.NewGuid();
            var userId2 = Guid.NewGuid();
            var user = new IdentityUser<Guid>
            {
                Id = userId,
                Email = $"{userId}@test.com",
                UserName = $"{userId}",
            };

            var store = GetSubject();

            await store.CreateAsync(user);
            var userById = await store.FindByIdAsync(user.Id.ToString());
            var userByName = await store.FindByNameAsync(normalizer.NormalizeName($"{userId}"));

            user.UserName = $"{userId2}";
            await store.UpdateAsync(user);
            var userById2 = await store.FindByIdAsync(user.Id.ToString());
            var userByName2 = await store.FindByNameAsync(normalizer.NormalizeName($"{userId}"));
            var userByName3 = await store.FindByNameAsync(normalizer.NormalizeName($"{userId2}"));

            Assert.NotNull(userById);
            Assert.NotNull(userByName);
            Assert.NotNull(userById2);
            Assert.Null(userByName2);
            Assert.NotNull(userByName3);
        }

        private OrleansUserStore<IdentityUser<Guid>, IdentityRole<Guid>> GetSubject()
        {
            return GetSubject(out var _);
        }

        private OrleansUserStore<IdentityUser<Guid>, IdentityRole<Guid>> GetSubject(out OrleansRoleStore<IdentityUser<Guid>, IdentityRole<Guid>> roleStore)
        {
            roleStore = new OrleansRoleStore<IdentityUser<Guid>, IdentityRole<Guid>>(_cluster.Client);
            return new OrleansUserStore<IdentityUser<Guid>, IdentityRole<Guid>>(_cluster.Client, roleStore);
        }
    }
}