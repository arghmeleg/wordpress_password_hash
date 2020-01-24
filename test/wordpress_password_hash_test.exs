defmodule WordpressPasswordHashTest do
  use ExUnit.Case
  doctest WordpressPasswordHash

  test "hashes correctly" do
    # assert WordpressPasswordHash.check_password(
    #          "zAbFU5zOtStX9a0HOQem",
    #          "$P$BCQEkZ0JWtT/6l6bfECE/PIxETbbxH0"
    #        )

    IO.inspect(WordpressPasswordHash.encode64("input", 3))

    # refute WordpressPasswordHash.check_password(
    #          "not the correct pass",
    #          "$P$BCQEkZ0JWtT/6l6bfECE/PIxETbbxH0"
    #        )
  end
end
