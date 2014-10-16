typedef int Fixed;

void mm(Fixed a[2][2], Fixed b[2][2], Fixed o[2][2]);

int main()
{
	Fixed a[2][2] = { 1<<16, 3<<16, 4<<16, 5<<16 };
	Fixed b[2][2] = { -1<<16, 1<<16, 1<<16, -1<<16 };
	Fixed o[2][2];

	for (int i = 0; i < 10000000; ++i)
	{
		for (int j = 0; j < 1; ++j)
		{
			mm(a, b, o);
		}
	}
	
	return 0;
}