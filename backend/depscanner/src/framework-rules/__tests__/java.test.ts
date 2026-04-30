import { javaModule } from '../../tree-sitter-extractor/languages/java';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('Java framework detectors', () => {
  describe('spring', () => {
    it('detects @RequestMapping + @GetMapping class + method annotations', async () => {
      const file = await extractInline(
        javaModule,
        `
package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User findOne(@PathVariable Long id) {
        return null;
    }

    @PostMapping
    public User create(@RequestBody User user) {
        return user;
    }
}
        `,
        '/tmp/UserController.java',
        [dep('spring-web', 'org.springframework')],
      );
      const eps = entryPointsFor(file, 'spring');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/api/users/{id}');
      expect(byMethod.get('POST')).toBe('/api/users');
    });
  });

  describe('jaxrs', () => {
    it('detects @Path + @GET annotations', async () => {
      const file = await extractInline(
        javaModule,
        `
package com.example;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;

@Path("/items")
public class ItemResource {

    @GET
    @Path("/{id}")
    public Response get(@PathParam("id") String id) {
        return Response.ok().build();
    }

    @POST
    public Response create(String body) {
        return Response.status(201).build();
    }
}
        `,
        '/tmp/ItemResource.java',
        [dep('jakarta.ws.rs-api', 'jakarta.ws.rs')],
      );
      const eps = entryPointsFor(file, 'jaxrs');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/items/{id}');
      expect(byMethod.get('POST')).toBe('/items');
    });
  });

  describe('quarkus', () => {
    it('detects Quarkus REST endpoints via @Path', async () => {
      const file = await extractInline(
        javaModule,
        `
package com.example;

import io.quarkus.runtime.Quarkus;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/hello")
public class GreetingResource {
    @GET
    public String hello() {
        return "hello";
    }
}
        `,
        '/tmp/GreetingResource.java',
        [dep('quarkus-core', 'io.quarkus')],
      );
      const eps = entryPointsFor(file, 'quarkus');
      expect(eps.length).toBeGreaterThanOrEqual(1);
      expect(eps[0].routePattern).toBe('/hello');
      expect(eps[0].httpMethod).toBe('GET');
    });
  });

  describe('micronaut', () => {
    it('detects @Controller + @Get annotations', async () => {
      const file = await extractInline(
        javaModule,
        `
package com.example;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;

@Controller("/pets")
public class PetController {

    @Get("/{id}")
    public Pet find(Long id) { return null; }

    @Post
    public Pet create(Pet pet) { return pet; }
}
        `,
        '/tmp/PetController.java',
        [dep('micronaut-http', 'io.micronaut.http')],
      );
      const eps = entryPointsFor(file, 'micronaut');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/pets/{id}');
      expect(byMethod.get('POST')).toBe('/pets');
    });
  });
});
