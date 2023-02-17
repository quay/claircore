# testdata

## simple-ruby.tar

This layer is derived from a simple Ruby 3.2.1 image.

It was created by the following Dockerfile:

```
FROM ruby:3.2.1
RUN gem update --system 3.4.7 && gem install rake
```

The layer tar was extracted from the image (top layer).

## rails.tar

This layer is derived from a simple Ruby 3.2.1 image
with rails installed.

It was created by the following Dockerfile:

```
FROM ruby:3.2.1
RUN gem install rails
```

The layer tar was extracted from the image (top layer).
