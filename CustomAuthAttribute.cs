using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleMvcApp
{

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public class CustomAuthAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
        public CustomAuthAttribute() : base()
        {
            var res = base.Roles;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var res = base.Roles;
            var user = context.HttpContext.User;

            if (!user.Identity.IsAuthenticated)
            {
                return;
            }

            // you can also use registered services
            //var someService = context.HttpContext.RequestServices.GetService<ISomeService>();

            var isAuthorized = true;// someService.IsUserAuthorized(user.Identity.Name, _someFilterParameter);
            if (!isAuthorized)
            {
                context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                return;
            }
        }
    }

}
