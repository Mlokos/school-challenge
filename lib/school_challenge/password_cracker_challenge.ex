defmodule PasswordCrackerChallenge do
  @doc """
  Funkcja przyjmuje hash oryginalnego hasła
  Zwraca znalezione hasło na podstawie oryginalnego hasha
  jako listę znaków - np. 'abc'

  TIP: należy zwrócić uwagę, czy apostrofy są '' (lista znaków) czy "" (String, binary)
  """
  @chunk_size 3_000_000

  def guess_password(hash), do: guess_password(hash, 0)
  def guess_password(hash, n) do
    n * @chunk_size..(n + 1) * @chunk_size
    |> Enum.chunk_every(div(@chunk_size, 2))
    |> Enum.map(&(Task.async(fn -> check_list_of_numbers(&1, hash) end)))
    |> Enum.map(&Task.await/1)
    |> List.flatten()
    |> Enum.filter(&match?({true, _}, &1))
    |> case do
        [] -> guess_password(hash, n + 1)
        [true: x] -> x
      end
  end

  defp check_list_of_numbers(numbers, hash) do
    numbers
    |> Enum.map(&check_number(&1, hash))
  end

  defp check_number(number, hash) do
    number
    |> number_to_password('')
    |> check_password(hash)
  end

  defp number_to_password(0, ''), do: 'a'
  defp number_to_password(0, password), do: password
  defp number_to_password(number, password) do
    number
    |> rem(26)
    |> (fn(x) -> [x + 97] end).()
    |> (fn(x) -> number_to_password(div(number, 26), x ++ password) end).()
  end

  defp check_password(password, actual_password_hash) do
    {actual_password_hash == :crypto.hash(:sha512, password), password}
  end
end
