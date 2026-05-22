# SOURCE

Greenfield — no upstream taint-engine gem fixture.

The taint-engine fixture suite has Sinatra (Ruby) but not Rails. The
dogfood corpus needs a representative Rails fixture so the M5 gem
batch exercises a realistic ActiveRecord raw-SQL shape end-to-end.

Seeded categories mirror the django/express fixtures for uniformity.
