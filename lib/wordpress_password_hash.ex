defmodule WordpressPasswordHash do
  @moduledoc false

  require Bitwise

  @itoa64 "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @hex_0x3f 63

  def check_password(password, stored_hash) do
    # if ( strlen( $password ) > 4096 ) {
    #   return false;
    # }

    # $hash = $this->crypt_private($password, $stored_hash);
    hash = crypt_private(password, stored_hash)

    # if ($hash[0] == '*')
    #   $hash = crypt($password, $stored_hash);

    hash === stored_hash
  end

  defp crypt_private(password, setting) do
    output = "*0"
    # if (substr($setting, 0, 2) == $output)
    #   $output = '*1';
    id = String.slice(setting, 0..3)
    IO.puts("id #{id}")
    # if ($id != '$P$' && $id != '$H$')
    #   return $output;
    # $count_log2 = strpos($this->itoa64, $setting[3]);
    IO.puts("String.at(setting, 3) #{String.at(setting, 3)}")
    count_log2 = strpos(@itoa64, String.at(setting, 3))
    IO.puts("count_log2 #{count_log2}")
    # $count = 1 << $count_log2;
    count = Bitwise.<<<(1, count_log2)
    IO.puts("count #{count}")
    # $salt = substr($setting, 4, 8);
    salt = String.slice(setting, 4..11)
    IO.puts("salt #{salt}")
    # if (strlen($salt) != 8)
    #   return $output;

    # if (PHP_VERSION >= '5') {
    #   $hash = md5($salt . $password, TRUE);
    #   do {
    #     $hash = md5($hash . $password, TRUE);
    #   } while (--$count);
    # } else {
    #   $hash = pack('H*', md5($salt . $password));
    #   do {
    #     $hash = pack('H*', md5($hash . $password));
    #   } while (--$count);
    # }
    hash =
      Enum.reduce(0..(count - 1), md5_base16_lower(salt <> password), fn _n, hash ->
        # |> Base.encode16()

        n = md5_base16_lower(hash <> password)
        if _n > 8185, do: hash |> IO.inspect()
        n
      end)

    IO.puts("hash #{inspect(hash)}")

    # $output = substr($setting, 0, 12);
    output = String.slice(setting, 0..12)
    IO.puts("output #{output}")
    # $output .= $this->encode64($hash, 16);
    output = output <> encode64(hash, count)
    IO.puts("output #{output}")
  end

  defp strpos(string, character) do
    string
    |> :binary.match(character)
    |> elem(0)
  end

  defp md5_base16_lower(string) do
    :md5
    |> :crypto.hash(string)
    |> Base.encode16(case: :lower)
  end

  # defp encode64(input, count) do
  def encode64(input, count) do
    # function encode64($input, $count)
    # {
    #   $output = '';
    #   $i = 0;
    output = ""
    value = nil
    i = 0
    #   do {
    {_i, output, _value} = encode64_1(i, input, output, count, value)
    output
  end

  defp encode64_1(i, input, output, count, value) when i < count do
    #     $value = ord($input[$i++]);

    value = ord(String.at(input, i))
    i = i + 1

    #     $output .= $this->itoa64[$value & 0x3f];
    output = output <> String.at(@itoa64, Bitwise.&&&(value, @hex_0x3f))

    #     if ($i < $count)
    #       $value |= ord($input[$i]) << 8;
    value =
      if i < count do
        value = value + Bitwise.<<<(ord(String.at(input, i)), 8)
      else
        value
      end

    #     $output .= $this->itoa64[($value >> 6) & 0x3f];
    output = output <> String.at(@itoa64, Bitwise.&&&(Bitwise.>>>(value, 6), @hex_0x3f))

    #     if ($i++ >= $count)
    #       break;

    encode64_2(i, input, output, count, value)
  end

  defp encode64_1(i, input, output, count, value), do: {i, output, value}

  defp encode64_2(i, input, output, count, value) when i < count do
    #     if ($i < $count)
    #       $value |= ord($input[$i]) << 16;
    i = i + 1

    value =
      if i < count do
        value + Bitwise.<<<(ord(String.at(input, i)), 16)
      else
        value
      end

    #     $output .= $this->itoa64[($value >> 12) & 0x3f];
    output = output <> String.at(@itoa64, Bitwise.&&&(Bitwise.>>>(value, 12), @hex_0x3f))

    #     if ($i++ >= $count)
    #       break;
    {i, output, value} = encode64_3(i, input, output, count, value)

    #     $output .= $this->itoa64[($value >> 18) & 0x3f];

    #   } while ($i < $count);
    encode64_1(i, input, output, count, value)

    #   return $output;
    # }
  end

  defp encode64_2(i, input, output, count, value), do: {i, output, value}

  defp encode64_3(i, input, output, count, value) when i < count do
    i = i + 1

    output = output <> String.at(@itoa64, Bitwise.&&&(Bitwise.>>>(value, 18), @hex_0x3f))
    {i, output, value}
  end

  defp encode64_3(i, input, output, count, value), do: {i, output, value}

  defp ord(nil), do: 0

  defp ord(character) do
    character
    |> String.to_charlist()
    |> hd()
  end
end
